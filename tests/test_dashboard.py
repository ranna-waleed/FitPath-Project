from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
import time
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def test_dashboard():
    # Initialize the Chrome driver
    driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
    driver.maximize_window()
    
    try:
        # Open the home page
        driver.get("http://127.0.0.1:5000/")
        time.sleep(2)  

        # Click on the login button
        login_button = driver.find_element(By.XPATH, "/html/body/section[1]/div/div[1]/div/div[3]/div/div/div[2]/div[2]/a")
        login_button.click()
        time.sleep(2) 

        # Fill in the username
        username_field = driver.find_element(By.XPATH, '//*[@id="floatingText"]')
        username_field.send_keys("User1")
        time.sleep(1) 

        # Fill in the password
        password_field = driver.find_element(By.XPATH, '//*[@id="floatingPassword"]')
        password_field.send_keys("user123")
        time.sleep(1)  

        # Click on the login button
        submit_button = driver.find_element(By.XPATH, '//*[@id="submit"]')
        submit_button.click()
        time.sleep(3)  

        # Redirect to dashboard
        driver.get("http://127.0.0.1:5000/dashboard")
        time.sleep(2)  

        # Click on the next specific element (view meals)
        next_specific_element_1 = driver.find_element(By.XPATH, '/html/body/section[2]/div/div[3]/div/a[1]')
        next_specific_element_1.click()
        time.sleep(2) 

        # Redirect to dashboard
        driver.get("http://127.0.0.1:5000/dashboard")
        time.sleep(2)  

        # Click on the specific element (update health metric)
        specific_element = driver.find_element(By.XPATH, '/html/body/section[2]/div/div[3]/div/a[2]')
        specific_element.click()
        time.sleep(2)  

        # Write 70 in weight section
        weight_field = driver.find_element(By.XPATH, '//*[@id="weight"]')
        weight_field.clear()
        weight_field.send_keys("70")
        time.sleep(1) 

        # Write 170 in height section
        height_field = driver.find_element(By.XPATH, '//*[@id="height"]')
        height_field.clear()
        height_field.send_keys("170")
        time.sleep(1) 

        # Write 20 in BMI section
        bmi_field = driver.find_element(By.XPATH, '//*[@id="bmi"]')
        bmi_field.clear()
        bmi_field.send_keys("20")
        time.sleep(1)  

        # Write note in notes section
        notes_field = driver.find_element(By.XPATH, '//*[@id="notes"]')
        notes_field.clear()
        notes_field.send_keys("This is a test note.")
        time.sleep(1) 

        # Click save button
        save_button = driver.find_element(By.XPATH, '/html/body/section[2]/div/div/div/form/button')
        save_button.click()
        time.sleep(2)  
         
        # Click on the next specific element (update goal setting)
        next_specific_element = driver.find_element(By.XPATH, '/html/body/section[2]/div/div[3]/div/a[3]')
        next_specific_element.click()
        time.sleep(2) 

        # Select "Maintain" from the goal dropdown
        goal_dropdown = Select(driver.find_element(By.XPATH, '//*[@id="goal"]'))
        goal_dropdown.select_by_visible_text("Maintain")
        time.sleep(1) 

        # Write activity level in activity level section
        activity_level_dropdown = Select(driver.find_element(By.XPATH, '//*[@id="activity_level"]'))
        activity_level_dropdown.select_by_visible_text("Medium")
        time.sleep(1)  

        # Write exercise frequency in exercise frequency section
        exercise_frequency_field = driver.find_element(By.XPATH, '//*[@id="exercise_frequency"]')
        exercise_frequency_field.clear()
        exercise_frequency_field.send_keys("3")
        time.sleep(1) 

        # Write target date in target date section
        target_date_field = driver.find_element(By.XPATH, '//*[@id="target_date"]')
        target_date_field.clear()
        target_date_field.send_keys("1-2-2023")
        time.sleep(1) 

        # Write note in notes section
        notes_goal_section = driver.find_element(By.XPATH, '//*[@id="notes"]')
        notes_goal_section.clear()
        notes_goal_section.send_keys("This is a test note for goal setting.")
        time.sleep(1)  

        # Click save button
        save_button_goal_section = driver.find_element(By.XPATH, '/html/body/section[2]/div/div/div/form/button')
        save_button_goal_section.click()
        time.sleep(2)  

        # Click on the next specific element (your workout)
        next_specific_element_2 = driver.find_element(By.XPATH, '/html/body/section[2]/div/div[3]/div/a[4]')
        next_specific_element_2.click()
        time.sleep(2)  

        # Click on the specified element
        specified_element = driver.find_element(By.XPATH, '/html/body/section[2]/div/div/div/div/a')
        specified_element.click()
        time.sleep(2)  

        # Redirect to dashboard
        driver.get("http://127.0.0.1:5000/dashboard")
        time.sleep(2)

        # Click on the next specific element (Your nutrition plan)
        next_specific_element_3 = driver.find_element(By.XPATH, '/html/body/section[2]/div/div[3]/div/a[5]')
        next_specific_element_3.click()
        time.sleep(2)  

        # Click on the specified element
        specified_element_1 = driver.find_element(By.XPATH, '/html/body/section[2]/div/div/div/div/a')
        specified_element_1.click()
        time.sleep(2) 

        home = driver.find_element(By.XPATH, '/html/body/header/div/div[1]/div[2]/nav/ul/a')
        home.click()
        time.sleep(2)

    finally:
        driver.quit()

if __name__ == "__main__":
    test_dashboard()