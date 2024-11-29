from flask_login import current_user
from models import *
from models import *

db_helper = DatabaseHelper(db.session)

def getProblems():
    problems = Problem.query.filter_by(user_id=current_user.id).all()

    return [{'description': p.description, 'status': p.status} for p in problems]

def add_problem(description):
    """
    Adds a new problem to the database.
    :param description: The problem description.
    :return: Tuple (success: bool, message: str)
    """
    if not description:
        return False, "Description is required."
    try:
        new_problem = Problem(description=description, status='Pending')
        db.session.add(new_problem)
        db.session.commit()
        return True, "Problem added successfully!"
    except Exception as e:
        db.session.rollback()
        return False, f"Error adding problem: {str(e)}"

def update_problem_status(problem_id, new_status):
    """
    Updates the status of a problem.
    :param problem_id: ID of the problem to update.
    :param new_status: New status to set.
    :return: Tuple (success: bool, message: str)
    """
    if new_status not in ['Pending', 'In Progress', 'Resolved']:
        return False, "Invalid status selected."
    try:
        problem = Problem.query.get(problem_id)
        if not problem:
            return False, "Problem not found."
        problem.status = new_status
        db.session.commit()
        return True, "Problem status updated successfully!"
    except Exception as e:
        db.session.rollback()
        return False, f"Error updating status: {str(e)}"