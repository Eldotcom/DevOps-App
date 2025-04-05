from flask import Blueprint, render_template, request, redirect, url_for, flash, session

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            session['username'] = username
            flash("Logged in successfully.")
            return redirect(url_for('dashboard.dashboard'))
        else:
            flash("Username required.")
    return render_template('login.html')
