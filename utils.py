from flask_login import current_user
from sqlalchemy import text
from app import db


def getCurrentrole():
    user_id = current_user.id
    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT RoleId FROM UserRoles WHERE UserId = :user_id"), {"user_id": user_id}
        )
        role_id = result.scalar()  

        if role_id is None:
            return []  
        # Fetch the claims for the retrieved RoleId
        claims_result = connection.execute(
            text("SELECT ClaimValue FROM RoleClaims WHERE RoleId = :role_id"), {"role_id": role_id}
        )

        # Fetch all claims as a list of strings
        claims = claims_result.fetchall()
        claims_list = [claim[0] for claim in claims]

    return claims_list




def getName():
    if current_user.is_authenticated:
        user_id = current_user.id
        print(f"Authenticated user ID: {user_id}")
        try:
            with engine.connect() as connection:
                result = connection.execute(
                    text("SELECT UserName FROM Users WHERE Id = :user_id AND State = 1"), {"user_id": user_id}
                )
                UserName = result.scalar()
                print("UserName: ", UserName)
                return UserName
        except Exception as e:
            print(f"Error fetching user name: {e}")
            return 'Guest'
    else:
        print("User is not authenticated")
        return 'Guest'
    



    def getProblems():
    if not current_user.is_authenticated:
        return []
    return Problem.query.filter_by(user_id=current_user.id).all()



    def authorize(module, action):
    claims_list = getCurrentrole()  # Get the current role's claims

    # Check if the module and action are in the claims_list
    for claim in claims_list:
        # Check if both module and action are present in the claim
        if f"{module}.{action}" in claim:
            return True  # Authorization granted
    
    return False  # Authorization denied



    