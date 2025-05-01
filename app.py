from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
from pydantic import BaseModel, ValidationError
import json
from datetime import datetime

# Initialize database and login manager

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey"


db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


class Users(UserMixin,db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    
    def get_id(self):
        return str(self.user_id)

class Event(db.Model):
    event_id = db.Column(db.Integer, primary_key=True)
    event_type=db.Column(db.String(500),nullable = False)
    event_name=db.Column(db.String(500),nullable=False)
    event_size= db.Column(db.Integer)
    venue= db.Column(db.String(500))
    planned_for = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))  # Add this line
    


with app.app_context():
    db.create_all()
    
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

@app.route("/")
def home():
    events = []
    if current_user.is_authenticated:
        # Fetch events for the current user
        events = Event.query.filter_by(user_id=current_user.user_id).all()
    return render_template("home.html", events=events)

@app.route('/register', methods=["GET", "POST"])
def register():
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if Users.query.filter_by(username=username).first():
            return render_template("register.html", error="Username already taken!")

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")

        new_user = Users(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("login"))
    
    return render_template("register.html")
    

# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = Users.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return render_template("login.html", error="Invalid username or password")
    
    return render_template("login.html")  # No need to pass undefined user

@app.route("/event", methods=["POST", "GET"])
@login_required
def create_event():
    if request.method == "GET":
        return render_template("event.html")
        
    # Handle POST request
    try:
        event_name = request.form.get("eventname")
        event_type = request.form.get("eventtype")
        event_size = request.form.get("eventsize")
        venue = request.form.get("venue")
        planned_for_str = request.form.get("planned_for")
        
        # Convert string date to datetime object
        planned_for = datetime.strptime(planned_for_str, '%Y-%m-%d')
        
        new_event = Event(
            event_name=event_name,
            event_type=event_type,
            event_size=event_size,
            venue=venue,
            planned_for=planned_for,
            user_id=current_user.user_id 
        )
        
        db.session.add(new_event)
        db.session.commit()
        
        return redirect(url_for('home'))
    except ValueError:
        # Handle invalid date format
        return render_template("event.html", error="Invalid date format")
    except Exception as e:
        # Handle other errors
        return render_template("event.html", error=f"Error creating event: {str(e)}")
        
@app.route('/get_event/<int:event_id>', methods=["GET", "POST"])
def get_event(event_id):
    event = Event.query.filter_by(event_id=event_id, user_id=current_user.id).first_or_404()
     
    return render_template('home.html',event=event)
    
                           
                           
                              
@app.route('/delete_event/<int:event_id>', methods=["POST"])
@login_required
def delete_event(event_id):
    event = Event.query.filter_by(event_id=event_id).first_or_404()
    
    # Optional: Check if the event belongs to the current user
    if event.user_id != current_user.user_id:
        return redirect(url_for('home'),error="Attempting to delete the event failed!!")
    
    db.session.delete(event)
    db.session.commit()
    
    return redirect(url_for('home'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))  # Use 'home' instead of '/'

if __name__ == '__main__':
    app.run(debug=True)