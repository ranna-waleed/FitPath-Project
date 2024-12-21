from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

# Set up the WebDriver
driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
driver.maximize_window()
# Test the registration functionality
def test_register():
    # Open the home page
    driver.get('http://127.0.0.1:5000/')
    time.sleep(2)  

    # Click on the register link
    driver.find_element(By.XPATH, '/html/body/section[1]/div/div[1]/div/div[3]/div/div/div[2]/div[1]/a').click()
    time.sleep(2) 
    
    # Wait for the registration form to be visible
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, '//*[@id="full_name"]'))
    )
    time.sleep(2)  
    
    # Fill in the registration form
    driver.find_element(By.XPATH, '//*[@id="full_name"]').send_keys('your_full_name')
    time.sleep(2)  
    driver.find_element(By.XPATH, '//*[@id="username"]').send_keys('your_username')
    time.sleep(2) 
    driver.find_element(By.XPATH, '//*[@id="email"]').send_keys('your_email@example.com')
    time.sleep(2)  
    driver.find_element(By.XPATH, '//*[@id="password"]').send_keys('your_password')
    time.sleep(2)  
    driver.find_element(By.XPATH, '//*[@id="confirm_password"]').send_keys('your_password')
    time.sleep(2)  
    
    # Click the register button
    driver.find_element(By.XPATH, '//*[@id="submit"]').click()
    time.sleep(2) 
    
    # Wait for the confirmation or dashboard to load
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, '//div[@id="user-dashboard"]'))
    )
    print("Registration successful and dashboard loaded.")

test_register()

time.sleep(10) 
driver.quit()