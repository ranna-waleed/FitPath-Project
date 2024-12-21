import unittest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time

class TestLoginFunctionality(unittest.TestCase):
    def setUp(self):
        """Set up the WebDriver before each test."""
        self.driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
        self.driver.implicitly_wait(10)  # Implicit wait for elements to load
    
    def test_login(self):
        """Test the login functionality."""
        driver = self.driver
        
        # Open the home page
        driver.get('http://127.0.0.1:5001/')
        time.sleep(2)
        
        # Click on the login link
        driver.find_element(By.XPATH, '/html/body/section[1]/div/div[1]/div/div[3]/div/div/div[2]/div[2]/a').click()
        time.sleep(2)
        
        # Wait for the login form to be visible
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//*[@id="floatingText"]'))
        )
        
        # Enter login credentials
        driver.find_element(By.XPATH, '//*[@id="floatingText"]').send_keys('User1')
        driver.find_element(By.XPATH, '//*[@id="floatingPassword"]').send_keys('user123')
        
        # Click the login button
        driver.find_element(By.XPATH, '//*[@id="submit"]').click()
        
        # Wait for the dashboard to load
        WebDriverWait(driver, 10).until(
            EC.presence_of_element_located((By.XPATH, '//div[@id="user-dashboard"]'))
        )
        
        # Assert that the dashboard is loaded
        dashboard = driver.find_element(By.XPATH, '//div[@id="user-dashboard"]')
        self.assertIsNotNone(dashboard, "Dashboard did not load.")
        print("Login successful and dashboard loaded.")
    
    def tearDown(self):
        """Close the browser after each test."""
        self.driver.quit()

# Run the tests
if __name__ == '__main__':
    unittest.main()
