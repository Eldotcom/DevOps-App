from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
import os
import time

def get_driver(browser="chrome", headless=True):
    if browser == "chrome":
        options = ChromeOptions()
        if headless:
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
        service = ChromeService(ChromeDriverManager().install())
        return webdriver.Chrome(service=service, options=options)

    elif browser == "firefox":
        options = FirefoxOptions()
        if headless:
            options.add_argument("--headless")
        service = FirefoxService(GeckoDriverManager().install())
        return webdriver.Firefox(service=service, options=options)

    else:
        raise ValueError("Unsupported browser: " + browser)

def test_ui_login():
    browser = os.getenv("BROWSER", "chrome")       # ברירת מחדל: chrome
    headless = os.getenv("HEADLESS", "true") == "true"  # ברירת מחדל: true

    driver = get_driver(browser, headless)

    try:
        driver.get("http://127.0.0.1:5000/login")
        time.sleep(1)

        driver.find_element(By.ID, "username").send_keys("testuser")
        driver.find_element(By.ID, "password").send_keys("testpass")
        driver.find_element(By.XPATH, '//button[@type="submit"]').click()
        time.sleep(2)

        assert "dashboard" in driver.page_source or "Logged in successfully" in driver.page_source

    finally:
        driver.quit()
