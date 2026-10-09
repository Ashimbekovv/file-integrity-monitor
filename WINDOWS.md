# Запуск на Windows без WSL

Нужны Windows 10/11 и Python 3.11 или новее. Ubuntu и права администратора для
работы приложения не требуются. Сканер пропускает символические ссылки, junction
и другие reparse points. Для первого опыта используйте обычную локальную папку,
а не папку OneDrive.

## 1. Установите Python и скачайте проект

Установите Python с [python.org](https://www.python.org/downloads/windows/).
При установке включите Python Launcher (`py`). После установки откройте новое
окно PowerShell и проверьте версию:

```powershell
py -3 --version
```

Скачайте репозиторий через GitHub: **Code → Download ZIP**, распакуйте архив и
откройте PowerShell в распакованной папке, где находится `pyproject.toml`.
Если установлен Git, вместо ZIP можно выполнить:

```powershell
git clone https://github.com/Ashimbekovv/file-integrity-monitor.git
cd file-integrity-monitor
```

## 2. Установите приложение

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\python.exe -m fim --help
```

Здесь используется Python напрямую из виртуального окружения. Запускать
`Activate.ps1` и менять execution policy PowerShell не нужно.

## 3. Быстрая демонстрация одной командой

```powershell
.\.venv\Scripts\python.exe examples\demo.py
```

Демонстрация сама создаст временные файлы, baseline и отдельный ключ. Она проверит
неизменённые файлы, изменение содержимого, добавление, удаление, историю и подпись.
В конце появится `Demo passed`, а все временные данные будут удалены. Ваши личные
файлы демонстрация не использует.

## 4. Проверка вручную

Выполните эти команды один раз в папке проекта. Названия начинаются с `demo-`,
чтобы их было легко отличить от ваших данных:

```powershell
New-Item -ItemType Directory demo-files, demo-state, demo-keys
Set-Content -Path demo-files\example.txt -Value 'Hello' -Encoding utf8
.\.venv\Scripts\python.exe -c "import secrets; from pathlib import Path; Path('demo-keys/demo.key').open('xb').write(secrets.token_bytes(32))"

.\.venv\Scripts\python.exe -m fim init .\demo-files --db .\demo-state\baseline.db --key .\demo-keys\demo.key
.\.venv\Scripts\python.exe -m fim scan .\demo-files --db .\demo-state\baseline.db --key .\demo-keys\demo.key --verbose
```

Результат первой проверки: `Unchanged: 1`. Измените только демонстрационный файл:

```powershell
Set-Content -Path demo-files\example.txt -Value 'Changed' -Encoding utf8
.\.venv\Scripts\python.exe -m fim scan .\demo-files --db .\demo-state\baseline.db --key .\demo-keys\demo.key
```

Результат: `Modified: 1`. Добавьте новый файл и удалите исходный:

```powershell
Set-Content -Path demo-files\new.txt -Value 'New file' -Encoding utf8
Remove-Item -LiteralPath demo-files\example.txt
.\.venv\Scripts\python.exe -m fim scan .\demo-files --db .\demo-state\baseline.db --key .\demo-keys\demo.key

.\.venv\Scripts\python.exe -m fim history --db .\demo-state\baseline.db --key .\demo-keys\demo.key --verbose
.\.venv\Scripts\python.exe -m fim verify-baseline --db .\demo-state\baseline.db --key .\demo-keys\demo.key
```

Результат: `New: 1` и `Deleted: 1`. Код завершения `scan` при обнаружении изменений
равен 1 — это ожидаемый результат. Ошибки возвращают 2; успешная чистая проверка — 0.

Сканирование не обновляет исходный baseline. Не запускайте `init` повторно с той
же базой и не генерируйте новый ключ для существующей базы. Для нового доверенного
состояния после проверки изменений укажите новое имя базы.

Для проверки своей папки замените `demo-files` на её полный путь в кавычках.
База должна находиться вне сканируемой папки, а ключ — вне неё и в отдельном
каталоге от базы. Для настоящих ключей ограничьте доступ средствами Windows ACL;
простое разделение по папкам не защищает от вредоносной программы под вашим
пользователем.

## Автоматические тесты

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q -ra
```

Некоторые тесты создания symlink могут быть пропущены, если Windows не разрешает
их создание без Developer Mode. Тесты junction и основные проверки работают без
него. Подробные ограничения защиты baseline описаны в [README](README.md).
