#!/usr/bin/env python3

import html
import inspect
import json
import os
import random
import re
import string
import sys
import time
import pickle
from enum import Enum
from sys import argv

# Make all random more random.
import requests

random = random.SystemRandom()

""" <config> """
# SERVICE INFO
PORT = 8888
EXPLOIT_NAME = argv[0]

# DEBUG -- logs to stderr, TRACE -- log HTTP requests
DEBUG = os.getenv("DEBUG", True)
TRACE = os.getenv("TRACE", False)
""" </config> """

class FakeSession(requests.Session):
    """
    FakeSession reference:
        - `s = FakeSession(host, PORT)` -- creation
        - `s` mimics all standard request.Session API except of fe features:
            -- `url` can be started from "/path" and will be expanded to "http://{host}:{PORT}/path"
            -- for non-HTTP scheme use "https://{host}/path" template which will be expanded in the same manner
            -- `s` uses random browser-like User-Agents for every requests
            -- `s` closes connection after every request, so exploit get splitted among multiple TCP sessions
    Short requests reference:
        - `s.post(url, data={"arg": "value"})`          -- send request argument
        - `s.post(url, headers={"X-Boroda": "DA!"})`    -- send additional headers
        - `s.post(url, auth=(login, password)`          -- send basic http auth
        - `s.post(url, timeout=1.1)`                    -- send timeouted request
        - `s.request("CAT", url, data={"eat":"mice"})`  -- send custom-verb request
        (response data)
        - `r.text`/`r.json()`  -- text data // parsed json object
    """

    USER_AGENTS = [
        """Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/11.1 Safari/605.1.15""",
        """Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36""",
        """Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201""",
        """Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13; ) Gecko/20101203""",
        """Mozilla/5.0 (Windows NT 5.1) Gecko/20100101 Firefox/14.0 Opera/12.0""",
    ]

    def __init__(self, host, port):
        super(FakeSession, self).__init__()
        if port:
            self.host_port = "{}:{}".format(host, port)
        else:
            self.host_port = host

    def prepare_request(self, request):
        r = super(FakeSession, self).prepare_request(request)
        r.headers["User-Agent"] = random.choice(FakeSession.USER_AGENTS)
        r.headers["Connection"] = "close"
        return r

    # fmt: off
    def request(self, method, url,
                params=None, data=None, headers=None,
                cookies=None, files=None, auth=None, timeout=None, allow_redirects=True,
                proxies=None, hooks=None, stream=None, verify=None, cert=None, json=None,
                ):
        if url[0] == "/" and url[1] != "/":
            url = "http://" + self.host_port + url
        else:
            url = url.format(host=self.host_port)
        r = super(FakeSession, self).request(
            method, url, params, data, headers, cookies, files, auth, timeout,
            allow_redirects, proxies, hooks, stream, verify, cert, json,
        )
        if TRACE:
            print("[TRACE] {method} {url} {r.status_code}".format(**locals()))
        return r
    # fmt: on


def check(host: str):
    # TODO: reuse created events
    
    s1 = FakeSession(host, PORT)
    s2 = FakeSession(host, PORT)

    username1, password1 = _gen_user()
    username2, password2 = _gen_user()

    _register(s1, username1, password1)
    _register(s2, username2, password2)

    _log(f"Checking can create and get event")
    _check_put_get(s1, username1)
    
    _log("Checking private ended events are displayed ")
    _check_ended(s1, s2, username1)

    _log("Checking event share")
    _check_share(s1, s2, username1, username2)

    _log("Checking event filtering")
    _check_filter(s1, s2)

    _log("Checking event import/export")
    _check_pickle(s1, username1)

    die(ExitStatus.OK, "Check ALL OK")


def _check_pickle(s, username):
    event1 = _gen_event(private=False)
    id1 = _put(s, event1)

    event2 = _gen_event(private=True)
    id2 = _put(s, event2)

    r = s.get(f"/export?id={id1}&id={id2}")
    if r.status_code != 200:
        _log(f"Unexpected /export status code {r.status_code} with ids {[id1, id2]}")
        die(ExitStatus.MUMBLE, f"Unexpected /export status code {r.status_code}")

    exported = r.text
    splitted = exported.split("\n")
    if len(splitted) != 2:
        die(ExitStatus.MUMBLE, f"Unexpected export format")

    body = splitted[1]
    body = bytes.fromhex(body)


    event1["private"] = False
    event2["private"] = True
    serialized = bytes()
    for event in [event1, event2]:
        data = {
            "start": int(event["start"]),
            "end": int(event["end"]),
            "details": event["details"],
            "private": event["private"],
            "name": event["name"],
        }
        serialized += pickle.dumps(data)

    if body != serialized:
        _log(f"Unexpected export format\nExpected:\n{serialized}Got:\n{body}")
        die(ExitStatus.MUMBLE, f"Unexpected export format")

    r = s.post("/import", files={"file": ("export", exported)})
    if r.status_code != 200:
        _log(f"Unexpected /import status code {r.status_code} with response {r.text}")
        die(ExitStatus.MUMBLE, f"Unexpected /import status code {r.status_code}")

    res = re.findall(r'Imported event: <a href="/event/(\d+)/">\1</a>', r.text)
    if len(res) != 2:
        die(ExitStatus.MUMBLE, f"Didn't get message of all new imported events")

    if len(set([id1, id2, int(res[0]), int(res[1])])) != 4:
        die(ExitStatus.MUMBLE, f"Events has not been imported")

    event1["user"] = username
    imported1 = _get(s, res[0])
    _compare_events(imported1, event1)

    event2["user"] = username
    imported2 = _get(s, res[1])
    _compare_events(imported2, event2)



def _check_filter(s1, s2):
    event = _gen_event(private=False)
    id = _put(s1, event)

    params = {"start": event["start"], "end": event["end"]}
    r = s1.get(f"/?start={event['start']}&end={event['end']}")  # passing 'params' breaks checker for some reason
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected / status code {r.status_code} with params {params}")

    pattern = r'<td id="name">{}<\/td>[^\0]*?<a href="\/event\/{}\/">'.format(re.escape(event["name"]), id)
    match = re.search(pattern, html.unescape(r.text), re.DOTALL)
    if match is None:
        _log(f"Can't find event {event} in / with params {params} with body {r.text}")
        die(ExitStatus.MUMBLE, f"Can't find filtered event in /")

    event = _gen_event(private=True)
    end = int(time.time()) - 100#sec
    start = end - 100#sec
    event["end"] = end
    event["start"] = start

    id = _put(s1, event)

    params = {"start": event["start"]-1, "end": event["end"]+1}
    r = s2.get(f"/ended?start={params['start']}&end={params['end']}")  # passing 'params' breaks checker for some reason
    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected / status code {r.status_code} with params {params}")

    pattern = r'<td id="name">{}<\/td>[^\0]*?<a href="\/event\/{}\/">'.format(re.escape(event["name"]), id)
    match = re.search(pattern, html.unescape(r.text), re.DOTALL)
    if match is None:
        _log(f"Can't find event {event} in /ended with params {params} with body {r.text}")
        die(ExitStatus.MUMBLE, f"Can't find filtered event in /ended")

    return


def _check_put_get(s, username):
    event = _gen_event(private=False)

    id = _put(s, event)
    got = _get(s, id)
    event["user"] = username

    _compare_events(event, got)


def put(host: str, flag_id: str, flag: str, vuln: int):
    s = FakeSession(host, PORT)
    username, password = _gen_user()

    _register(s, username, password)

    event = _gen_event(private=True)
    flagstore = ["name", "details"][vuln-1]
    event[flagstore] = flag

    event_id = _put(s, event)

    jd = json.dumps(
        {
            "flag_id": event_id,
            "username": username,
            "password": password,
        }
    )

    print(jd, flush=True)  # It's our flag_id now! Tell it to jury!
    die(ExitStatus.OK, f"{jd}")


def _put(s, event):
    try:
        r = s.post("/create", data=event, allow_redirects=False)
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to put flag in service: {e}")

    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /create status code {r.status_code}")

    redirect = r.headers.get("Location")
    if not redirect:
        die(ExitStatus.MUMBLE, "No redirect in /create")

    try:
        id = int(redirect.split("/")[-2])
    except Exception as e:
        die(ExitStatus.MUMBLE, f"Failed to parse event id: {e}")

    return id


def get(host: str, flag_id: str, flag: str, vuln: int):
    print("START GET")
    try:
        data = json.loads(flag_id)
        if not data:
            raise ValueError
    except:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Unexpected flagID from jury: {flag_id}! Are u using non-RuCTF checksystem?",
        )

    if len(data) != 3 and not all(
        key in data for key in ["flag_id", "username", "password"]
    ):
        die(ExitStatus.CHECKER_ERROR, f"Invalid flagID from jury: {flag_id}")

    s = FakeSession(host, PORT)
    _login(s, data["username"], data["password"])

    _log("Getting flag using api")
    event = _get(s, data["flag_id"])

    flagstore = ["name", "details"][vuln-1]
    if flag not in event.get(flagstore):
        die(ExitStatus.CORRUPT, f"Can't find a flag in {event.get('name')}")
    
    die(ExitStatus.OK, f"All OK! Successfully retrieved a flag from api")


def _get(s, flag_id):
    try:
        r = s.get(
            f"/event/{flag_id}/",
        )
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to get user questions: {e}")

    if r.status_code != 200:
        die(ExitStatus.MUMBLE, f"Unexpected /event/{flag_id} code {r.status_code}")

    body = r.text

    pattern = r"<strong>(.*?):</strong><p.*?>(.*?)</p>"
    matches = re.findall(pattern, body)

    event = {key.lower(): value for key, value in matches}

    return event


def _check_share(s1, s2, username1, username2):

    event = _gen_event(private=True)
    id = _put(s1, event)

    r = s1.post(f"/event/{id}/share", data={"username": username2}, allow_redirects=False)
    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /event/{id}/share status code {r.status_code}")

    got = _get(s2, id)
    event["user"] = username1

    _compare_events(event, got)


def _check_ended(s1, s2, username1):
    event = _gen_event(private=True)
    end = int(time.time()) - 100#sec
    start = end - 100#sec
    event["end"] = str(end)
    event["start"] = str(start)

    id = _put(s1, event)
    got = _get(s2, id)

    event["user"] = username1

    _compare_events(event, got)


def _compare_events(a: dict, b: dict):
    a, b = a.copy(), b.copy()
    
    a.pop("private", None)
    b.pop("private", None)
    
    for k, v in a.items():
        a[k] = html.unescape(v)

    for k, v in b.items():
        b[k] = html.unescape(v)
    
    if a != b:
        _log(f"Events differ:\n\t{sorted(a.items())}\n\t{sorted(b.items())}")
        die(ExitStatus.MUMBLE, f"Events differ")


def _register(s, username, password):
    try:
        r = s.post(
            "/register",
            data={"username": username, "password": password},
            allow_redirects=False,
        )
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to register in service: {e}")

    if r.status_code != 302:
        _log(f"Unexpected /register code {r.status_code} with body {r.text}")
        die(ExitStatus.MUMBLE, f"Unexpected /register code {r.status_code}")

    if len(r.cookies) == 0:
        die(ExitStatus.MUMBLE, f"Failed to register in service: {e}")

    return


def _login(s, username, password):
    try:
        r = s.post(
            "/login",
            data={"username": username, "password": password},
            allow_redirects=False,
        )
    except Exception as e:
        die(ExitStatus.DOWN, f"Failed to login in service: {e}")

    if r.status_code != 302:
        die(ExitStatus.MUMBLE, f"Unexpected /login code {r.status_code}")

    if len(r.cookies) == 0:
        die(ExitStatus.MUMBLE, f"Failed to register in service: {e}")

    return


def _gen_user():
    names = [
        "John", "Jane", "Alice", "Bob", "Charlie", "David", "Eve", "Frank", "Grace", "Heidi", "Ivan", "Grisha", "Kate",
        "Laura", "Michael", "Nina", "Oscar", "Paul", "Quincy", "Rachel", "Steve", "Tina", "Ursula", "Victor", "Wendy", "Xavier", "Yvonne", "Zach"
    ]

    nick = [
        "Ace", "Blaze", "Crusher", "Dynamo", "Eagle", "Flash", "Ghost", "Hawk", "Ice", "Jester", "King", "Lion", "Maverick", "Ninja", "Oracle", "Phoenix", "Quicksilver", "Raven", "Shadow", "Titan", "Viper", "Wolf", "Xenon", "Yeti", "Zephyr",
        "Albatross", "Bolt", "Cyclone", "Drake", "Echo", "Falcon", "Gale", "Harrier", "Icicle", "Jaguar", "Kestrel", "Leopard", "Meteor", "Nebula", "Osprey", "Puma", "Quasar", "Raptor", "Scorpion", "Tornado", "Urchin", "Vulture", "Whirlwind", "X-ray", "Yak", "Zeppelin",
        "Anaconda", "Barracuda", "Cobra", "Dragon", "Eel", "Ferret", "Gorilla", "Hippo", "Impala", "Jackal", "Koala", "Llama", "Mongoose", "Narwhal", "Octopus", "Penguin", "Quokka", "Raccoon", "Shark", "Tiger", "Uakari", "Viper", "Walrus", "Xerus", "Yabby", "Zebra"
    ]

    username = (
        f"{random.choice(names)} {random.choice(nick)} {random.randint(1, 100000)}"
    )
    password = rand_string(12)

    return username, password


def _gen_event(private=False) -> dict:
    group_actions = [
        "going to {place}",
        "having a {event_type} party",
        "watching a {event_type} game",
        "attending a {event_type} concert",
        "having a {event_type} meeting",
        "going on a {event_type} trip",
    ]

    places = [
        "a restaurant of puke",
        "a Spunch Bob's cafe",
        "a Exhibitionist park",
        "a boogers museum",
        "a theater of one actor",
        "the beach",
        "the mountains of shit",
        "a shopping mall",
        "a sports CS:GO arena",
        "an amusement park",
        "a monkey zoo",
        "a bowling alley",
        "a children movie theater",
        "an anime opening karaoke bar",
        "a resort of horror",
        "a campground",
        "a vineyard",
        "a brewery for one-handed",
        "a golf course",
        'a ski resort "Spread your legs"',
        "a water park DROWN",
        "a art gallery of grubs",
        "a flea market",
        "a convention center",
        "a conference",
        "a water cooking class",
        "a hiking trail EVEREST",
        "a camping trip BAIKAL",
        "a road trip KOLYMA",
        "a cruise in North Korea",
        "a flight in Kongo republic",
        "a train ride Pusan",
        "a sightseeing tour Chelyabinsk",
        "a pie-eating contest EAT OR DIE",
        "a funny hat factory",
        "a whoopee cushion emporium",
        "a laughter yoga studio",
        "a rubber chicken farm",
        "a practical joke supply store",
        "a circus of the absurd",
        "a pun museum",
        "a stand-up comedy boot camp",
        "a wacky invention lab",
        "a slapstick stunt school",
        "a dank meme exhibition",
        "a rage comic convention",
        "a rickroll festival",
        "a trollface meetup",
        "a bad luck brian gathering",
        "a grumpy cat fan club",
        "a numa numa dance party",
        "a harlem shake flashmob",
        "a dilbert convention",
        "a wat lady meetup",
        "a pepe the frog cosplay",
        "an advice animal exhibition",
        "JOJO anime cosplay meetup",
        "Club Veselyh & Nahodchivyh",
        "Anonymous alchogolic club",
    ]

    event_types = [
        "team1 6(4)?",
        "school of saint Patrick",
        "familyGuy festival",
        "graduation in extrasensory perception",
        "baby shower",
        "bridal shower",
        "bachelorette party",
        "bachelor party",
        "fundraiser",
        "charity",
        "reunion of GRAZHDANSKAYA OBORONA",
        "picnic na obochine",
        "BarbieHeimer school staging",
        "potluck",
        "Fortnite game night",
        "Zeleniy Slonik movie night",
        "I love books club (Da etot lyubitel boksa s odnogo udara lyazhet)",
        "150 rubles wine in plastic bag tasting",
        "one-handed beer tasting",
        "stone cooking class",
        "straight line art class",
        "dance class",
        "yoga class",
        "fitness class",
        "chihuahua sports tournament",
        "chess sports game",
        "dull music festival",
        "comedy show Krivoe Zerkalo",
        "magic show",
        "circus of Cumbez",
        "fair story",
        "expo My name is Tony Stark. I'm a genius, billionaire, playboy, philanthropist.",
    ]

    individual_actions = [
        "binge-watch cat videos on YouTube",
        "have an intense staring contest with the dog",
        "attempt to cook a gourmet meal from random ingredients",
        "chase squirrels in the park",
        "have a full-blown conversation with a potted plant",
        "try to fit into childhood clothes",
        "have a dance party with an imaginary partner",
        "attempt to speak in bizarre accents",
        "attempt to learn a new language from a children's book",
        "have a burping contest with friends",
        "attempt to juggle everyday household items",
        "have a laugh-off challenge",
        "attempt to do a comedy routine for pets",
        "try to make puns in a different language",
        "have a costume party with just one participant",
        "attempt to create a new dance move",
        "attempt to learn ventriloquism with a sock puppet",
        "have a staring contest with a mirror",
        "attempt to beatbox using household sounds",
        "try to come up with a new comedy sketch",
        "attempt to do impersonations of famous people",
        "have a karaoke party for one",
        "try to tell the world's funniest joke",
        "attempt to create a new comedy catchphrase",
        "try to come up with a hilarious new insult",
        "attempt to create a new comedy routine for kids",
        "have a stand-up comedy show for pets",
        "try to come up with a funny new nickname for friends",
        "attempt to create a new comedy skit",
        "have a comedy roast with inanimate objects",
        "try to come up with a funny new pick-up line",
        "try to find the power button on a laptop",
        "search for a cell tower",
        "call the repair service",
        "impersonate a grunting cat",
        "sit like a patriarch",
        "rub your palm to launch a helicopter",
        "go shake your fat",
        "try to make a meme in real life",
        "hang out with pixels",
        "laugh at Arnold Schwarzenegger memes",
        "add a meme phrase to a conversation",
    ]

    event_type = random.choice(["group", "individual"])

    if event_type == "group":
        action_template = random.choice(group_actions)

        if "{place}" in action_template:
            activity = action_template.format(place=random.choice(places))
        elif "{event_type}" in action_template:
            event_type = random.choice(event_types)
            activity = action_template.format(event_type=event_type)
        else:
            activity = action_template

        details = f"{activity}"
    else:
        activity = random.choice(individual_actions)
        details = f"{activity}"

    name = random.choice(event_types)

    start = int(time.time()) + random.randint(1, 60 * 60)  # 1 second to 1 hour from now

    if private:
        duration = random.randint(
            2 * 24 * 60 * 60, 3 * 24 * 60 * 60
        )  # from 2 days to 3 days
    else:
        duration = random.randint(5 * 60, 1 * 60 * 60)  # from 5 mins to 1 hour
    end = start + duration

    event = {
        "start": str(start),
        "end": str(end),
        "details": details,
        "private": private,
        "name": name,
    }

    if private:
        event["private"] = "on"
    else:
        del event["private"]

    return event


def rand_string(
    n=12, alphabet=string.ascii_uppercase + string.ascii_lowercase + string.digits
):
    return "".join(random.choice(alphabet) for _ in range(n))


def _log(obj):
    if DEBUG and obj:
        caller = inspect.stack()[1].function
        print(f"[{caller}] {obj}", file=sys.stderr)
    return obj


class ExitStatus(Enum):
    OK = 101
    CORRUPT = 102
    MUMBLE = 103
    DOWN = 104
    CHECKER_ERROR = 110


def die(code: ExitStatus, msg: str):
    if msg:
        print(msg, file=sys.stderr)
    exit(code.value)


def info():
    # print('{"vulns": 2, "timeout": 30, "attack_data": ""}', flush=True, end="")
    print("vulns: 1:1", flush=True, end="")
    exit(101)


def _main():
    try:
        cmd = argv[1]
        hostname = argv[2]
        if cmd == "get":
            fid, flag, vuln = argv[3], argv[4], int(argv[5])
            get(hostname, fid, flag, vuln)
        elif cmd == "put":
            fid, flag, vuln = argv[3], argv[4], int(argv[5])
            put(hostname, fid, flag, vuln)
        elif cmd == "check":
            check(hostname)
        elif cmd == "info":
            info()
        else:
            raise IndexError
    except IndexError:
        die(
            ExitStatus.CHECKER_ERROR,
            f"Usage: {argv[0]} check|put|get IP FLAGID FLAG VULN",
        )


if __name__ == "__main__":
    _main()
