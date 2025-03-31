from datetime import datetime

def convert_to_timestamp(date):
    """
    Date could be in the format of "2021-01-01T00:00"
    or timestamp already.
    """
    try:
        return float(date)
    except ValueError:
        pass

    try:
        date_format = "%Y-%m-%dT%H:%M"
        date_object = datetime.strptime(date, date_format)
        timestamp = date_object.timestamp()
        return float(timestamp)
    except ValueError:
        return float(0)