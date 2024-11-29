from flask_login import current_user
from models import *
from models import *

def getPending_Problems(status='Pending'):
    problems = Problem.query.filter_by(user_id=current_user.id, status=status).all()
    return [{'description': p.description, 'status': p.status} for p in problems]

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