import sys
url=sys.argv[1]

import copy

import requests
import json
import time
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

csp_presence = False
def csrf_token(url):#ищет csrf-токен на странице
    csrfToken_in_input = False
    csrfToken_in_meta = False
    response = requests.get(url)
    content = response.content
    soup = bs(content, "html.parser")
    all_inputs = soup.find_all('input')
    for input in all_inputs:
        if(input.has_attr('name')):
            value = input['name']
            if 'csrf' in value or 'token' in value:
                if input['value']:
                    csrfToken_in_input = True
    all_meta = soup.find_all('meta')
    for meta in all_meta:
        if(meta.has_attr('name')):
            value = meta['name']
            if 'csrf' in value:
                csrfToken_in_meta = True
    if csrfToken_in_input or csrfToken_in_meta:
        return 1#есть csrf-токен
    return 0#нет csrf-токена
def inner_HTML(url):
    # Инициализируем сессию
    session = requests.Session()
    # получаем HTML-контент
    html = session.get(url).content
    soup = bs(html, "html.parser")
    html_string = str(html)

    # получаем Java-Script файлы
    script_files = []
    innerhtml_in_js = 0
    if "innerhtml" in html_string.lower():
        innerhtml_in_js = 1
    for script in soup.find_all("script"):
        if script.attrs.get("src"):
            script_url = urljoin(url, script.attrs.get("src"))
            script_files.append(script_url)
    for i in range(0, len(script_files)):
        url = script_files[i]
        response = requests.get(url)
        text = response.text
        text = text.lower()
        if "innerhtml" in text:
            innerhtml_in_js = 1
    response = requests.get(url)
    text = response.text
    text = text.lower()
    innerHTML_string = "innerhtml"
    if innerHTML_string in text or innerhtml_in_js:
        return 1  # есть innerHTML, который стоит заменить на innerText
    else:
        return 0  # нет innerHTML
def Dom_Purify(url):
    # Инициализируем сессию
    response_html = requests.get(url)
    session = requests.Session()
    # Получаем HTML-контент
    html = session.get(url).content
    soup = bs(html, "html.parser")
    html_string = str(html)
    # Получаем Java-Script файлы
    script_files = []
    dompurify_in_js=0
    if "dompurify" in html_string.lower():
        dompurify_in_js=1
    for script in soup.find_all("script"):
        if script.attrs.get("src"):
            script_url = urljoin(url, script.attrs.get("src"))
            script_files.append(script_url)
    for i in range(0,len(script_files)):
        url = script_files[i]
        response = requests.get(url)
        text = response.text
        text = text.lower()
        if "dompurify" in text:
            dompurify_in_js = 1
    text = response_html.text
    text = text.lower()
    if "dompurify" in text or dompurify_in_js:
         return 1#есть DOMPurify
    else:
        return 0#нет DOMPurify
def is_escaped(content, payload):
    escaped_lt = "&lt;"
    escaped_gt = "&gt;"
    escaped_quot = "&quot;"
    escaped_small_quot = '&#039;'
    escaped_amp = "&amp;"

    # Проверяем, экранированы ли основные символы
    if escaped_lt in content or escaped_gt in content or escaped_quot in content or escaped_small_quot in content or escaped_amp in content:
        # Вероятно, экранирование есть, но нужно проверить, экранирован ли payload целиком или частично
        escaped_payload = payload.replace("&", escaped_amp).replace("<", escaped_lt).replace(">", escaped_gt).replace('"', escaped_quot).replace("'", escaped_small_quot)
        if escaped_payload in content:
            return True  # Payload полностью экранирован

        # Проверяем отдельные элементы payload на частичное экранирование
        if "<script" in payload:
          if "&lt;script" in content:
            return True

        if ">" in payload:
          if "&gt;" in content:
            return True

        return False # Частичное экранирование, нужно смотреть внимательнее
    else:
        return False  # Payload не экранирован
def forms_on_page(url):
    #По url я получаю все формы на стнанице
    response = requests.get(url)
    time.sleep(1)

    content = response.content
    soup = bs(content, "html.parser")
    all_forms = soup.find_all("form")
    return all_forms

def inputs_in_form(form):
    details = {}
    # Получаю action у формы
    action_of_form = form.attrs.get("action", None)  # Используем None по умолчанию
    if action_of_form:
        action_of_form = action_of_form.lower()

    # Получаю метод формы
    method_of_form = form.attrs.get("method", "get").lower()

    # Получаю информацию о форме
    inputs = []
    all_form_elements = form.find_all(['input', 'textarea', 'select'])  # Ищем input, textarea и select

    for element in all_form_elements:
        tag_name = element.name  # Получаем имя тега ('input', 'textarea', 'select')
        input_type = element.attrs.get("type", "text") if tag_name == 'input' else tag_name # Для textarea и select type не нужен
        input_name = element.attrs.get("name")

        inputs.append({"tag": tag_name, "type": input_type, "name": input_name})  # Добавляем имя тега

    details["action"] = action_of_form
    details["method"] = method_of_form
    details["inputs"] = inputs
    return details #словарь содержит информацию о input-ах формы
def submitting_of_form(form_details, url, value):
    target_url = urljoin(url, form_details["action"])
    inputs = form_details["inputs"]
    data = {}
    csp_presence = False
    textarea_values = {}
    for input in inputs:
        input_name = input.get("name")

        if input["tag"] == "input" and input["type"] in ("text", "search", "email", "url", "tel", "password"):
            input["value"] = value
        elif input["tag"] == "textarea":
            input["value"]=value
        elif input["tag"] == "select":
            if "options" in input:
                if len(input["options"]) > 0:
                    input["value"] = input["options"][0]["value"]
                else:
                    input["value"] = value
            else:
                input["value"] = value
        input_value = input.get("value")
        if input_name and input_value is not None:
            data[input_name] = input_value


    if form_details["method"] == "post":
       
        response = requests.post(target_url, data=data)
        return response
    else:
        return requests.get(target_url, params=data)
def check_csp(csp):
    unsafe_inline = "unsafe" in csp or "inline" in csp
    unsafe_eval = "unsafe" in csp or "eval" in csp
    http = "http" in csp
    asterisk = "*" in csp
    if unsafe_inline or unsafe_eval or http or asterisk:
        return 0
    return 1

def vulnerability_scan(url):
    formsInfo=[]
    forms = forms_on_page(url)
    response=None
   
    js_script_arr = ['<iframe src="javascript:alert(`xss`)">', "<script>alert('XSS')</script>",
                 '<img src="" onerror="alert(`XSS`)">', '<a href="javascript:alert(`XSS`)">Click me</a>',
                 '<style>body {background-image: url("javascript:alert(`XSS`)");}</style>',
                 '<svg onload="alert(`XSS`)"></svg>', '<img src=x onerror=alert(1)>']

    for form in forms:
        payloads=[]
        forma_details=None
        for js_script in js_script_arr:
            
            form_details = inputs_in_form(form)
            forma_details=copy.deepcopy(form_details)
            response = submitting_of_form(form_details, url, js_script)
            
            content = response.content.decode()
            
            if js_script in content and is_escaped(content, js_script)==False:                
                payloads.append(js_script)

       
        headers = response.headers
        check = 1
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            check = check_csp(csp)
            csp_presence = True
        else:
            csp_presence = False
            check = 0
        if(len(payloads)):
            formsInfo.append({"form_details": forma_details, "is_vulnerable": True, "payloads": payloads, "csp_presence": csp_presence, "csp_is_right": check})#check-проверяет правильно ли установлен csp, DomPurify=1, если он есть =0, если его нет; innerHTML=1, если он есть,=0,если его нет; scrfToken=1, если есть, =0, если нет
        else:
            formsInfo.append({"form_details": forma_details, "is_vulnerable": False, "csp_presence": csp_presence, "csp_is_right": check})#check-проверяет правильно ли установлен csp, DomPurify=1, если он есть =0, если его нет; innerHTML=1, если он есть,=0,если его нет; scrfToken=1, если есть, =0, если нет

    if formsInfo:
        DomPurify = Dom_Purify(url)
        innerHTML = inner_HTML(url)
        csrfToken = csrf_token(url)
        formsInfo.append({"DomPurify": DomPurify, "innerHTML": innerHTML, "csrfToken": csrfToken})
    return json.dumps(formsInfo)

print(vulnerability_scan(url))