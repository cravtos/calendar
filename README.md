# Calendar

Сервис, реализующий календарь событий.

Авторы: [@Borgc](https://github.com/Borgc), [@anatolymedvedev](https://github.com/anatolymedvedev), [@Cravtos](https://github.com/Cravtos)

## Тэги
 * Web
 * Python
 * Crypto

## Уязвимости

### Возможность поделиться произвольным событием

[Эксплуатация](exploits/share.py):
1. Зарегистрироваться
2. Создать событие
3. Нажать кнопку "Поделиться"
4. Перехватить запрос
5. Подменить ID события на произвольное

### Insecure deserialization + Hash Length Extention

[Эксплуатация](exploits/deser.py):
1. Зарегистрироваться
2. Создать событие
3. Экспортировать календарь
4. Сделать пейлоад
5. Добавить пейлоад к оригинальному календарю с помощью hash length extention
6. Импортировать календарь

### NaN type confusion

[Эксплуатация](exploits/nan.py):
1. Зарегистрироваться
2. Применить фильтр окончания события с датой NaN

## Deploy

### Service

```
cd ./services/calendary
docker-compose up -d
```

### Checker

Интерфейс чекера соответствует описанию для ructf: https://github.com/HackerDom/ructf-2017/wiki/Интерфейс-«проверяющая-система-чекеры»

```
cd ./checkers
pip install -r ./requirements.txt
python3 ./calendary/checker.py
```

Для использование с ructf jury, необходимо изменить формат вывода функции `info` в [чекере](checkers/calendary/checker.py): раскоментировать закоментированную строчку и наоборот.
