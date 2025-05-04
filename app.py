from flask import Flask, render_template, request, url_for, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os
from pydantic import BaseModel, ValidationError
import json
from datetime import datetime
from deepgram import Deepgram
import elevenlabs
from pydub import AudioSegment
from io import BytesIO
import base64
from dateutil import parser

# Initialize database and login manager
# Use environment variables or default to empty strings if not set
dg_api_key = os.getenv('DEEPGRAM_API_KEY', '')
elevenlabs_api_key = os.getenv('ELEVENLABS_API_KEY', '')

# Initialize API clients if keys are available
if dg_api_key:
    dg_client = Deepgram(dg_api_key)
else:
    dg_client = None
    print("Warning: DEEPGRAM_API_KEY not set. Voice processing will not work.")

if elevenlabs_api_key:
    elevenlabs.set_api_key(os.getenv('ELEVENLABS_API_KEY'))
else:
    print("Warning: ELEVENLABS_API_KEY not set. Voice response generation will not work.")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "supersecretkey"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class Users(UserMixin, db.Model):
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    events = db.relationship('Event', backref='user', lazy=True)
    
    def get_id(self):
        return str(self.user_id)

class Event(db.Model):
    event_id = db.Column(db.Integer, primary_key=True)
    event_type = db.Column(db.String(500), nullable=False)
    event_name = db.Column(db.String(500), nullable=False)
    event_size = db.Column(db.Integer)
    venue = db.Column(db.String(500))
    planned_for = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))

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
            # Store user ID in session for voice agent
            session['user_id'] = user.user_id
            return redirect(url_for('home'))
        else:
            return render_template("login.html", error="Invalid username or password")
    
    return render_template("login.html")

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
@login_required
def get_event(event_id):
    event = Event.query.filter_by(event_id=event_id, user_id=current_user.user_id).first_or_404()
     
    return render_template('event_detail.html', event=event)
    
@app.route('/all_events', methods=["GET", "POST"])
@login_required
def get_events():
    user_events = Event.query.filter_by(user_id=current_user.user_id).all()
    
    return render_template('dashboard.html', user_events=user_events)                    
                              
@app.route('/delete_event/<int:event_id>', methods=["POST"])
@login_required
def delete_event(event_id):
    event = Event.query.filter_by(event_id=event_id).first_or_404()
    
    # Check if the event belongs to the current user
    if event.user_id != current_user.user_id:
        return redirect(url_for('home'), error="Attempting to delete the event failed!!")
    
    db.session.delete(event)
    db.session.commit()
    
    return redirect(url_for('home'))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    if 'user_id' in session:
        session.pop('user_id')
    return redirect(url_for('home'))

# Voice agent routes
@app.route('/voice-agent')
@login_required
def voice_agent():
    return render_template('voice_agent.html')

@app.route('/process-voice-command', methods=['POST'])
@login_required
def process_voice_command():
    try:
        # Get audio file from request
        audio_file = request.files.get('audio')
        
        if not audio_file:
            print("No audio file found in request")
            return jsonify({
                'text_response': "No audio file received. Please try again.",
                'audio_response': ""
            }), 400
        
        # Log the audio file details
        print(f"Received audio file: {audio_file.filename}, Content Type: {audio_file.content_type}")
        
        # Directly use the audio data without pydub processing to avoid FFmpeg dependency
        audio_data = audio_file.read()
        
        # Use Deepgram to transcribe the audio
        try:
            # Initialize Deepgram client
            dg_api_key = os.getenv('DEEPGRAM_API_KEY', '')
            if not dg_api_key:
                return jsonify({
                    'text_response': "Deepgram API key not configured. Please set the DEEPGRAM_API_KEY environment variable.",
                    'audio_response': ""
                }), 500
            
            dg_client = Deepgram(dg_api_key)
            
            # Send the audio directly to Deepgram without saving to file
            source = {'buffer': audio_data, 'mimetype': 'audio/webm'}
            response = dg_client.transcription.sync_prerecorded(source, {
                'punctuate': True,
                'model': 'nova-2'
            })
            
            # Extract the transcript
            transcript = response['results']['channels'][0]['alternatives'][0]['transcript']
            print(f"Transcription: {transcript}")
            
            # Process the voice command
            response_text = handle_voice_command(transcript, current_user.user_id)
            
            # Check if ElevenLabs API key is set for audio response generation
            elevenlabs_api_key = os.getenv('ELEVENLABS_API_KEY', '')
            audio_response_base64 = ""
            
            if elevenlabs_api_key:
                try:
                    import elevenlabs
                    import base64
                    
                    elevenlabs.set_api_key(elevenlabs_api_key)
                    
                    # Generate speech response
                    audio = elevenlabs.generate(
                        text=response_text,
                        voice="Rachel",
                        model="eleven_monolingual_v1"  # Use v1 for wider compatibility
                    )
                    
                    # Convert to base64 for sending in JSON
                    audio_response_base64 = base64.b64encode(audio).decode('ascii')
                except Exception as e:
                    print(f"ElevenLabs audio generation error: {str(e)}")
                    # Continue without audio response if it fails
            
            # Return the response
            return jsonify({
                'transcript': transcript,
                'text_response': response_text,
                'audio_response': audio_response_base64
            })
            
        except Exception as e:
            print(f"Deepgram transcription error: {str(e)}")
            return jsonify({
                'text_response': f"I couldn't understand what you said. Error: {str(e)}",
                'audio_response': ""
            }), 500
        
    except Exception as e:
        # Log the full error for debugging
        import traceback
        error_details = traceback.format_exc()
        print(f"Error in process_voice_command: {str(e)}\n{error_details}")
        
        return jsonify({
            'text_response': f"Sorry, I encountered an error: {str(e)}",
            'audio_response': ""
        }), 500
def handle_voice_command(transcript, user_id):
    """Process voice commands and return appropriate responses with more flexible pattern matching."""
    # Convert to lowercase for easier matching
    transcript = transcript.lower().strip()
    print(f"Processing command: '{transcript}'")  # Add this for debugging
    
    # Add more variations of the "show events" command
    show_events_patterns = [
        "what events do i have", 
        "what events do i have booked", 
        "show me my events",
        "show my events",
        "list my events",
        "do i have any events",
        "view my events",
        "what's on my calendar",
        "what is on my calendar",
        "what do i have scheduled",
        "what's scheduled",
        "my events",
        "my bookings"
    ]
    
    # Check for event queries - use partial matching instead of exact phrases
    for pattern in show_events_patterns:
        if pattern in transcript:
            print(f"Matched show events pattern: '{pattern}'")  # Debug log
            # Use our existing function to get user events
            events = Event.query.filter_by(user_id=user_id).order_by(Event.planned_for).all()
            
            if not events:
                return "You don't have any events booked."
            
            # Format the date for speech
            next_event = events[0]
            event_date = next_event.planned_for.strftime("%B %d, %Y")
            
            if len(events) == 1:
                return f"You have one event. It's {next_event.event_name} on {event_date} at {next_event.venue}."
            else:
                return f"You have {len(events)} events. Your next event is {next_event.event_name} on {event_date} at {next_event.venue}."
    
    # More flexible event creation handling
    create_event_patterns = [
        "create event",
        "schedule event", 
        "new event",
        "add event",
        "book event",
        "make event"
    ]
    
    # First check if this is a creation intent
    is_create_intent = False
    matched_pattern = ""
    for pattern in create_event_patterns:
        if pattern in transcript:
            is_create_intent = True
            matched_pattern = pattern
            print(f"Matched create event pattern: '{pattern}'")
            break
    
    if is_create_intent:
        # This is a creation command, now parse it more flexibly
        try:
            # Extract date using regex and dateutil
            import re
            from dateutil import parser
            from datetime import datetime, timedelta
            
            # Default values
            event_name = "Untitled Event"
            planned_date = datetime.now() + timedelta(days=1)  # Default to tomorrow
            venue = "TBD"
            event_type = "Other"
            
            # Try to extract date with various patterns
            date_patterns = [
                r'(?:on|for|at)?\s+(\w+\s+\d+(?:st|nd|rd|th)?)',  # May 2nd, April 3rd
                r'(?:on|for|at)?\s+(\d+(?:st|nd|rd|th)?\s+\w+)',  # 2nd May, 3rd April
                r'(?:on|for|at)?\s+(\d{1,2}[/-]\d{1,2}(?:[/-]\d{2,4})?)'  # 5/2, 5/2/23, 5-2-2023
            ]
            
            date_match = None
            for pattern in date_patterns:
                matches = re.findall(pattern, transcript)
                if matches:
                    date_match = matches[0]
                    print(f"Found date match: {date_match}")
                    break
            
            # Parse the date if found
            if date_match:
                try:
                    planned_date = parser.parse(date_match, fuzzy=True)
                    print(f"Parsed date: {planned_date}")
                except:
                    # If date parsing fails, check for common terms
                    if "tomorrow" in transcript:
                        planned_date = datetime.now() + timedelta(days=1)
                    elif "next week" in transcript:
                        planned_date = datetime.now() + timedelta(days=7)
                    print(f"Using fallback date: {planned_date}")
            
            # Extract location with "in", "at", or "location" patterns
            location_patterns = [
                r'(?:in|at|location)\s+([a-zA-Z\s]+?)(?:\s+(?:on|for|type|called|named)|\s*$)',  # "in tampa", "at conference center"
            ]
            
            location_match = None
            for pattern in location_patterns:
                matches = re.findall(pattern, transcript)
                if matches:
                    location_match = matches[0].strip()
                    print(f"Found location match: {location_match}")
                    venue = location_match
                    break
            
            # Extract event type with "for" or "type" patterns
            type_patterns = [
                r'(?:for|type)\s+([a-zA-Z\s]+?)(?:\s+(?:on|in|at|called|named)|\s*$)',  # "for conference", "type meeting"
            ]
            
            type_match = None
            for pattern in type_patterns:
                matches = re.findall(pattern, transcript)
                if matches:
                    type_match = matches[0].strip()
                    print(f"Found type match: {type_match}")
                    event_type = type_match
                    break
            
            # Try to extract name from "called" or "named" patterns
            name_patterns = [
                r'(?:called|named)\s+([a-zA-Z\s]+?)(?:\s+(?:on|in|at|for|type)|\s*$)',  # "called team meeting"
            ]
            
            name_match = None
            for pattern in name_patterns:
                matches = re.findall(pattern, transcript)
                if matches:
                    name_match = matches[0].strip()
                    print(f"Found name match: {name_match}")
                    event_name = name_match
                    break
            
            # If no specific name was found but we have type, use that as the name
            if event_name == "Untitled Event" and type_match:
                event_name = type_match.title()  # Use the type as the name and capitalize it
            
            # Special case handling for commands like "create event May 2 in tampa for conference"
            if event_name == "Untitled Event":
                # Remove the creation command prefix
                remaining_text = transcript.replace(matched_pattern, "").strip()
                
                # If we have a date match, remove that
                if date_match:
                    remaining_text = remaining_text.replace(date_match, "").strip()
                
                # Remove location indicators
                if location_match:
                    for prefix in ["in", "at", "location"]:
                        remaining_text = remaining_text.replace(f"{prefix} {location_match}", "").strip()
                
                # Remove type indicators
                if type_match:
                    for prefix in ["for", "type"]:
                        remaining_text = remaining_text.replace(f"{prefix} {type_match}", "").strip()
                
                # Clean up extra spaces and punctuation
                remaining_text = re.sub(r'\s+', ' ', remaining_text).strip()
                remaining_text = re.sub(r'^[,\s]+|[,\s]+$', '', remaining_text)
                
                # If anything meaningful is left, use it as the event name
                if remaining_text and len(remaining_text) > 2:
                    event_name = remaining_text.title()
                elif type_match:  # Fallback to type if we extracted one
                    event_name = type_match.title()
            
            # Create the event
            new_event = Event(
                event_name=event_name,
                event_type=event_type,
                event_size=0,  # Default size
                venue=venue,
                planned_for=planned_date,
                user_id=user_id
            )
            
            db.session.add(new_event)
            db.session.commit()
            
            # Return a confirmation with the extracted details
            date_str = planned_date.strftime("%B %d, %Y")
            return f"I've created an event called '{event_name}' on {date_str} at {venue}."
            
        except Exception as e:
            print(f"Event creation error: {str(e)}")
            import traceback
            traceback.print_exc()
            return f"I couldn't create your event. Please try again with a clearer format. Error: {str(e)}"
    
    # Delete events
    delete_event_patterns = [
        "delete event",
        "remove event",
        "cancel event",
        "delete the event"
    ]
    
    for pattern in delete_event_patterns:
        if pattern in transcript:
            try:
                # Simple extraction of event name
                if "called" in transcript:
                    event_name = transcript.split("called")[1].strip()
                    # Find the event by name
                    event = Event.query.filter_by(user_id=user_id, event_name=event_name).first()
                    
                    if event:
                        db.session.delete(event)
                        db.session.commit()
                        return f"I've deleted the event {event_name}."
                    else:
                        return f"I couldn't find an event called {event_name}."
                else:
                    return "Please specify which event to delete by saying 'delete event called [event name]'."
            except Exception as e:
                print(f"Event deletion error: {str(e)}")
                return f"I couldn't delete the event. Error: {str(e)}"
    
    # Help command
    if "help" in transcript or "what can you do" in transcript:
        return ("I can help you manage your events. You can ask me to show your events, create a new event, " 
                "or delete an existing event. For example, try saying 'show my events', 'create event on May 2nd in Tampa for Conference', "
                "or 'delete event called Team Meeting'.")
    
    # Debug info to see what the actual transcript was
    print(f"No command matched for transcript: '{transcript}'")
    
    # Fallback response
    return f"I didn't understand that command. You said '{transcript}'. You can ask about your events, create a new event, or delete an event. Say 'help' for more information."

if __name__ == '__main__':
    app.run(debug=True)