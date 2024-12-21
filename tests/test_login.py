from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

def test_login():
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    driver.maximize_window()
    
    try:
        # Open the home page
        driver.get('http://127.0.0.1:5000/')
        time.sleep(2) 
        
        # Click on the login link
        driver.find_element(By.XPATH, '/html/body/section[1]/div/div[1]/div/div[3]/div/div/div[2]/div[2]/a').click()
        time.sleep(2) 
        
        # Wait for the login form to be visible
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="floatingText"]'))
        )
        time.sleep(2)  
        
        # Enter login credentials
        driver.find_element(By.XPATH, '//*[@id="floatingText"]').send_keys('User1')
        time.sleep(2)  
        driver.find_element(By.XPATH, '//*[@id="floatingPassword"]').send_keys('user123')
        time.sleep(2) 
        
        # Click the login button
        driver.find_element(By.XPATH, '//*[@id="submit"]').click()
        time.sleep(2) 
        
        # Wait for the dashboard to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//div[@id="user-dashboard"]'))
        )
        print("Login successful and dashboard loaded.")
    
    finally:

        driver.quit()

if __name__ == "__main__":
    test_login()