import requests
import hashlib
import os
import re
import json
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from tabulate import tabulate
import asyncio
import argparse
from playwright.async_api import async_playwright # ```:bash: playwright install ```

def autodetect_router_ip():
    for ip in ["192.168.0.1", "192.168.1.1", "192.168.8.1", "192.168.100.1"]:
        try:
            r = requests.get(f"http://{ip}/", timeout=2)
            if r.status_code in [200, 401]:
                print(f"[🌐] Обнаружен роутер по адресу {ip}")
                return ip
        except:
            continue
    print("[❌] Роутер не найден на известных адресах.")
    return "192.168.0.1"  # fallback

ROUTER_IP = autodetect_router_ip()
USERNAME = "admin"
PASSWORD = "admin"

parser = argparse.ArgumentParser()
parser.add_argument("--no-headless", action="store_true", help="Запуск браузера с UI для отладки")
args = parser.parse_args()

async def unlock_router_via_browser():
    print("[🔓] Попытка входа в админку через headless-браузер...")
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=not args.no_headless)
            page = await browser.new_page()
            await page.goto(f"http://{ROUTER_IP}/", wait_until="load", timeout=15000)
            try:
                await page.fill('input[name="router_username"]', USERNAME)
                await page.fill('#tbarouter_password', PASSWORD)
                await page.click('#btnSignIn')
                await page.wait_for_timeout(2000)
                print("[✅] Вход через UI выполнен.")
            except:
                print("[⚠️] Логин через UI не потребовался или не сработал.")
            await browser.close()
    except Exception as e:
        print(f"[ERROR] Ошибка Playwright входа: {e}")
        print("[⚠️] Повторная попытка...")
        await unlock_router_via_browser()

async def extract_imsi_from_browser():
    print("[🔍] Поиск IMSI через браузерный JS...")
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=not args.no_headless)
        page = await browser.new_page()
        await page.goto(f"http://{ROUTER_IP}/", wait_until="load")

        script = r"""
        (function findIMSIStrings(obj, path = 'window', visited = new WeakSet()) {
          if (visited.has(obj) || typeof obj !== 'object' || obj === null) return [];
          visited.add(obj);
          const results = [];
          for (const key in obj) {
            try {
              const val = obj[key];
              const fullPath = path + '.' + key;
              if (typeof val === 'object') {
                results.push(...findIMSIStrings(val, fullPath, visited));
              } else if (typeof val === 'string' && /^\d{14,16}$/.test(val)) {
                results.push(`${fullPath}: "${val}"`);
              }
            } catch (e) { continue; }
          }
          return results;
        })(window);
        """
        imsi_results = await page.evaluate(script)
        await browser.close()
        for line in imsi_results:
            match = re.search(r'"(\d{14,16})"', line)
            if match:
                print(f"[DEBUG] Найден IMSI в JS: {match.group(1)}")
                return match.group(1)
        print("[DEBUG] IMSI в JS не найден")
        return "-"

def get_router_xml_digest_force(file_name: str):
    url = f"http://{ROUTER_IP}/xml_action.cgi?method=get&module=duster&file={file_name}"
    uri = urlparse(url).path
    session = requests.Session()
    session.verify = False
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "User-Agent": "Mozilla/5.0",
        "Referer": f"http://{ROUTER_IP}/",
        "Accept": "application/xml, text/xml, */*"
    }

    resp1 = session.get(url, headers=headers)
    if resp1.status_code == 200 and resp1.text.strip().startswith("<"):
        return ET.fromstring(resp1.text), resp1.text

    if "WWW-Authenticate" not in resp1.headers:
        print(f"[⚠️] Нет WWW-Authenticate заголовка при запросе {file_name}, код {resp1.status_code}")
        return None, ""

    try:
        auth_fields = dict(
            item.strip().split("=", 1)
            for item in resp1.headers["WWW-Authenticate"].replace('Digest ', '').split(', ')
        )
        realm = auth_fields["realm"].strip('"')
        nonce = auth_fields["nonce"].strip('"')
        qop = auth_fields.get("qop", "auth").strip('"')
    except:
        print("[❌] Ошибка парсинга Digest полей")
        return None, ""

    cnonce = os.urandom(8).hex()
    nc = "00000001"
    HA1 = hashlib.md5(f"{USERNAME}:{realm}:{PASSWORD}".encode()).hexdigest()
    HA2 = hashlib.md5(f"GET:{uri}".encode()).hexdigest()
    response = hashlib.md5(f"{HA1}:{nonce}:{nc}:{cnonce}:{qop}:{HA2}".encode()).hexdigest()

    headers["Authorization"] = (
        f'Digest username="{USERNAME}", realm="{realm}", nonce="{nonce}", uri="{uri}", '
        f'response="{response}", qop={qop}, nc={nc}, cnonce="{cnonce}"'
    )

    resp2 = session.get(url, headers=headers)
    if resp2.status_code == 200 and resp2.text.strip().startswith("<"):
        return ET.fromstring(resp2.text), resp2.text

    return None, ""

def find_imsi(xml, raw_text=""):
    if xml is not None:
        for tag in ["imsi", "IMSI", "Imsi", "subscriber_id"]:
            val = xml.findtext(f".//{tag}")
            if val and val.strip() and val.lower() != "unknown":
                return val.strip()
    match = re.search(r"401\d{12}", raw_text)
    return match.group(0) if match else "-"

def resolve_operator(mcc_mnc):
    return {
        "401/77": "Altel",
        "401/99": "Tele2",
        "401/02": "Beeline",
        "401/01": "Kcell"
    }.get(mcc_mnc.strip(), "unknown")

def parse_status1(xml):
    if xml is None:
        return {}
    return {
        "IP-адрес": xml.findtext(".//ipv4", "-"),
        "Сетевая маска": xml.findtext(".//v4netmask", "-"),
        "Шлюз": xml.findtext(".//v4gateway", "-"),
        "DNS1": xml.findtext(".//v4dns1", "-"),
        "DNS2": xml.findtext(".//v4dns2", "-"),
        "IMEI": xml.findtext(".//IMEI", "-"),
        "ICCID": xml.findtext(".//ICCID", "-"),
        "RSSI": xml.findtext(".//rssi", "-") + " dBm",
        "Оператор": xml.findtext(".//operator_name", "-"),
        "SSID": xml.findtext(".//ssid", "-"),
    }

def parse_engineer(xml):
    if xml is None:
        return {}
    lte = xml.find(".//LTE")
    if lte is None:
        return {}
    return {
        "Band": lte.findtext("band", "-"),
        "Cell ID": lte.findtext("cellId", "-"),
        "RSRP (Main)": lte.findtext("mainRsrp", "-") + " dBm",
        "RSRP (Diversity)": lte.findtext("diversityRsrp", "-") + " dBm",
        "RSRQ (Main)": lte.findtext("mainRsrq", "-") + " dB",
        "RSRQ (Diversity)": lte.findtext("diversityRsrq", "-") + " dB",
        "SINR": lte.findtext("sinr", "-") + " dB",
        "CQI": lte.findtext("cqi", "-"),
        "MCC/MNC": f"{lte.findtext('mcc', '-')}" + "/" + f"{lte.findtext('mnc', '-')}"
    }

def parse_traffic(xml):
    if xml is None:
        return {}
    return {
        "Пакеты отправлены": xml.findtext(".//TxPackets", "-"),
        "Пакеты получены": xml.findtext(".//RxPackets", "-"),
    }

def save_info_as_json(info: dict, filename="lte_status.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(info, f, ensure_ascii=False, indent=4)
    print(f"[✅] Сохранено в {filename}")

def save_info_as_csv(info: dict, filename="lte_status.csv"):
    import csv
    with open(filename, "w", newline='', encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Параметр", "Значение"])
        for k, v in info.items():
            writer.writerow([k, v])
    print(f"[📁] Сохранено в {filename}")

async def update_router_status():
    all_info = {}

    await unlock_router_via_browser()

    status_xml, status_raw = get_router_xml_digest_force("status1")
    imsi = "-"
    if status_xml is not None:
        all_info.update(parse_status1(status_xml))
        imsi = find_imsi(status_xml, status_raw)

    eng_xml, eng_raw = get_router_xml_digest_force("Engineer_parameter")
    if eng_xml is not None:
        all_info.update(parse_engineer(eng_xml))
        if imsi == "-":
            imsi = find_imsi(eng_xml, eng_raw)

    traf_xml, traf_raw = get_router_xml_digest_force("qs_complete")
    if traf_xml is not None:
        all_info.update(parse_traffic(traf_xml))
        if imsi == "-":
            imsi = find_imsi(traf_xml, traf_raw)

    if imsi == "-":
        imsi = await extract_imsi_from_browser()

    all_info["IMSI"] = imsi
    mcc_mnc = all_info.get("MCC/MNC", "-")
    operator_name = all_info.get("Оператор", "unknown")
    all_info["Мобильный оператор"] = resolve_operator(mcc_mnc) if operator_name.lower() == "unknown" else operator_name

    return all_info

if __name__ == "__main__":
    info = asyncio.run(update_router_status())
    if info:
        print("\n📡 Текущий статус LTE-модема:\n")
        print(tabulate(info.items(), headers=["Параметр", "Значение"], tablefmt="fancy_grid"))
        save_info_as_json(info)
        save_info_as_csv(info)
    else:
        print("[!] Данные не получены.")
