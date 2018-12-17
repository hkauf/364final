### Import Statements ###
import os
import requests
import json
from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_script import Manager, Shell
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, FloatField, FileField, TextAreaField, SelectMultipleField, ValidationError, PasswordField, BooleanField
from wtforms.validators import Required, Length, Email, EqualTo, Regexp
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand

### Import Login Management ###
from flask_login import LoginManager, login_required, logout_user, login_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash

### App Configurations ###
app = Flask(__name__)
app.debug = True
app.use_reloader = True
app.config['SECRET_KEY'] = 'hard to guess string from si364'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI') or 'postgresql://halliekaufman@localhost/hkaufFinalProject'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

### App Setup ###
manager = Manager(app)
db = SQLAlchemy(app)
migrate = Migrate(app,db)
manager.add_command('db', MigrateCommand)

login_manager = LoginManager()
login_manager.session_protection = 'strong'
login_manager.login_view = 'login'
login_manager.init_app(app)

### Association Tables ###
watch_list = db.Table('watch_list', db.Column('movie_id', db.Integer, db.ForeignKey('Movies.id')), db.Column('playlist_id', db.Integer, db.ForeignKey('MovieWatchlist.id')))

### Set up Models ###
class User(UserMixin, db.Model):
	__tablename__ = 'Users'
	id = db.Column(db.Integer, primary_key = True)
	username = db.Column(db.String(225), unique = True, index = True)
	email = db.Column(db.String(64), unique = True, index = True)
	password_hash = db.Column(db.String(128))
	#one to many relationship: one user: many watchlists
	MovieWatchlist = db.relationship('MovieWatchlist', backref = 'User')

	@property
	def password(self):
		raise AttributeError('Password is not a readable attribute')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
	return User.query.get(int(user_id))

class MovieWatchlist(db.Model):
	__tablename__ = 'MovieWatchlist'
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(255))
	#One to many relationship: one user- many watchlists
	user_id = db.Column(db.Integer, db.ForeignKey('Users.id'))
	### Many to many
	movies = db.relationship('Movies', secondary = watch_list, backref = db.backref('MovieWatchlist', lazy = 'dynamic'), lazy = 'dynamic')

class Movies(db.Model):
	__tablename__ = 'Movies'
	id = db.Column(db.Integer,primary_key = True)
	title = db.Column(db.String)
	plot = db.Column(db.String)

class Related_Movies(db.Model):
	__tablename__ = 'Related_Movies'
	id = db.Column(db.Integer, primary_key = True)
	original_movie_title = db.Column(db.String)
	recommendations = db.Column(db.String)

### Forms ###
class RegistrationForm(FlaskForm):
	email = StringField('Email: ', validators= [Required(), Length(1,64), Email()])
	username = StringField('Username:',validators=[Required(),Length(1,64),Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0,'Usernames must have only letters, numbers, dots or underscores')])
	password = PasswordField('Password:',validators=[Required(),EqualTo('password2',message="Passwords must match")])
	password2 = PasswordField("Confirm Password:",validators=[Required()])
	submit = SubmitField('Register User')

	def validate_email(self, field):
		if User.query.filter_by(email = field.data).first():
			raise ValidationError('Email already registered')

	def validate_username(self,field):
		if User.query.filter_by(username = field.data).first():
			raise ValidationError('Username already taken')

class LoginForm(FlaskForm):
	email = StringField('Email', validators = [Required(), Length(1,64), Email()])
	password = PasswordField('Password', validators = [Required()])
	remember_me = BooleanField('Keep me logged in')
	submit = SubmitField('Log in')

class MovieSearchForm(FlaskForm):
	search = StringField('Search for a movie: ', validators = [Required()])
	submit = SubmitField('Search')

	def validate_movie_title(self, field):
		if len(field.data) <= 0:
			raise ValidationError('Oops! You did not search for anything. Please try again!')

class MovielistForm(FlaskForm):
	name = StringField('Movie List Name:', validators=[Required()])
	movies_included = SelectMultipleField('Movies to Include: ', validators=[Required()])
	submit = SubmitField('Create Movie List')

	def validate_list(self, field):
		if len(field.data) <1:
			raise ValidationError('Your movie list must have more than 1 movie!')

class UpdateMovielistName(FlaskForm):
	newname = StringField('What is your new movie list name?', validators = [Required()])
	submit = SubmitField('Update')

class UpdateButtonForm(FlaskForm):
	submit = SubmitField('Update')

class DeleteButtonForm(FlaskForm):
	submit = SubmitField('Delete')

### Helper Functions ###
def get_movie_by_id(id):
	m_id = Movies.query.filter_by(id = id).first()
	return m_id

def get_or_create_movie(db_session, title, plot):
	m = db_session.query(Movies).filter_by(title = title).first()
	if m:
		return m
	else:
		m= Movies(title = title, plot = plot)
		db_session.add(m)
		db_session.commit()
	return m

def get_or_create_related_movies(db_session, original_movie_title, recommendations):
	r_movies = db_session.query(Related_Movies).filter_by(original_movie_title = original_movie_title).first()
	if r_movies:
		return r_movies
	else:
		r_movies = Related_Movies(original_movie_title = original_movie_title, recommendations = recommendations)
		db_session.add(r_movies)
		db_session.commit()
	return r_movies

def get_or_create_watchlist(db_session, name, current_user, movie_list):
	Watchlist = db_session.query(MovieWatchlist).filter_by(name = name, user_id = current_user.id).first()
	if Watchlist:
		return Watchlist
	else:
		Watchlist = MovieWatchlist(name = name, user_id = current_user.id, movies = [])
		for m in movie_list:
			Watchlist.movies.append(m)
		db_session.add(Watchlist)
		db_session.commit()
		return Watchlist

def search_movie(search):
	movie = search
	baseurl = 'https://api.themoviedb.org/3/search/movie?api_key=9f212ff22336832af218802d70e73a08' + "&query="+movie
	r = requests.get(baseurl)
	data = json.loads(r.text)
	# recs_url = 'https://api.themoviedb.org/3/movie/{}/recommendations?api_key=9f212ff22336832af218802d70e73a08&language=en-US&page=1'.format(m_id)
	# recs_r = requests.get(recs_url)
	# recs_data = json.loads(recs_r.text)
	# recs = []
	# for x in range(5):
	# 	recs.append(recs_data['results'][x]['original_title'])
	return data

def search_recommended(search):
	movie = search
	baseurl = 'https://api.themoviedb.org/3/search/movie?api_key=9f212ff22336832af218802d70e73a08' + "&query="+movie
	r = requests.get(baseurl)
	data = json.loads(r.text)
	m_id = data['results'][0]['id']
	recs_url = 'https://api.themoviedb.org/3/movie/{}/recommendations?api_key=9f212ff22336832af218802d70e73a08&language=en-US&page=1'.format(m_id)
	recs_r = requests.get(recs_url)
	recs_data = json.loads(recs_r.text)
	m_title = movie
	recs = []
	for x in range(5):
		recs.append(recs_data['results'][x]['original_title'])
	return recs_data

### View Functions ###
app.errorhandler(404)
def page_not_found(e):
	return render_template('404.html'), 404

### Login Routes ###
@app.route('/login',methods=["GET","POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None and user.verify_password(form.password.data):
            login_user(user, form.remember_me.data)
            return redirect(request.args.get('next') or url_for('index'))
        flash('Invalid username or password.')
    return render_template('login.html',form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('index'))

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(email=form.email.data,username=form.username.data,password=form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You can now log in!')
        return redirect(url_for('login'))
    return render_template('register.html',form=form)

@app.route('/secret')
@login_required
def secret():
    return "Only authenticated users can do this! Try to log in or contact the site admin."

@app.route('/', methods = ['GET', 'POST'])
def index():
	return render_template('index.html')

@app.route('/movie_search')
def movie_search():
	form = MovieSearchForm()
	return render_template('movie_form.html', form = form)

@app.route('/movie_results', methods = ['GET'])
def movie_results():
	form = MovieSearchForm(request.args)
	title = None
	if request.method == 'GET' and form.validate():
		movie_search = search_movie(search = form.search.data)
		m_id = movie_search['results'][0]['id']
		title = movie_search['results'][0]['original_title']
		plot = movie_search['results'][0]['overview']
		get_movie = get_or_create_movie(db.session, title = title, plot= plot)
		title = Movies.query.filter_by(title = title).first()
		return render_template('movie_results.html', title = title)
	return redirect(url_for('movie_search'))

@app.route('/recommendation_info', methods = ['GET', 'POST'])
def search_recs():
	form = MovieSearchForm()
	recommendations = None
	if request.method == 'POST' and form.validate_on_submit():
		recs_search = search_recommended(search = form.search.data)
		recommendations = []
		m_title = form.search.data
		for x in range(5):
			recommendations.append((recs_search['results'][x]['original_title']))
		get_recs = get_or_create_related_movies(db.session, original_movie_title= m_title, recommendations = recommendations)
	return render_template('search_recs.html', form = form, recommendations = recommendations)

@app.route('/movies')
@login_required
def see_movies():
	movies = Movies.query.all()
	return render_template('all_movies.html', all_movies = movies)

@app.route('/recommendations')
@login_required
def see_recs():
	recommendations = Related_Movies.query.all()
	return render_template('all_recommendations.html', all_recommendations = recommendations)

@app.route('/createwatchlist',methods=["GET","POST"])
@login_required
def create_watchlist():
    form = MovielistForm()
    movies = Movies.query.all()
    choices = [(m.id, m.title) for m in movies]
    form.movies_included.choices = choices
    if request.method == 'POST':
        selectedmovie = form.movies_included.data
        movie_obj = [get_movie_by_id(int(id)) for id in selectedmovie]
        get_or_create_watchlist(db.session, name = form.name.data, current_user = current_user, movie_list = movie_obj)
        print('Watchlist Created!')
        return redirect(url_for('watchlists'))
    else:
        return render_template('create_watchlist.html', form = form)

@app.route('/watchlists',methods=["GET","POST"])
@login_required
def watchlists():
	delete = DeleteButtonForm()
	update = UpdateButtonForm()
	watchlists = MovieWatchlist.query.filter_by(user_id = current_user.id).all()
	return render_template('watchlists.html', watchlists = watchlists, delete = delete, update = update)

@app.route('/watchlist/<id_num>')
@login_required
def single_watchlist(id_num):
	delete = DeleteButtonForm()
	id_num = int(id_num)
	watchlist = MovieWatchlist.query.filter_by(id=id_num).first()
	movies = watchlist.movies.all()
	return render_template('watchlist.html',watchlist = watchlist, movies = movies, delete = delete)

@app.route('/delete/<watchlist>', methods= ['GET', 'POST'])
@login_required
def delete(watchlist):
	watchlist = MovieWatchlist.query.filter_by(name = watchlist).first()
	item_title = watchlist.name
	for x in watchlist.movies:
		db.session.delete(x)
	db.session.delete(watchlist)
	db.session.commit()
	flash('{} successfully deleted!'.format(watchlist.name))
	return redirect(url_for('watchlists'))

@app.route('/update/<watchlist>', methods = ['GET', 'POST'])
@login_required
def update_watchlist(watchlist):
	form = UpdateMovielistName()
	if form.validate_on_submit():
		newname= form.newname.data
		lst = MovieWatchlist.query.filter_by(name = watchlist).first()
		lst.name = newname
		db.session.commit()
		flash('{} watchlist has updated to {}'.format(watchlist, lst.name))
		return redirect(url_for('watchlists'))
	return render_template('updated_name.html', watchlist = watchlist, form = form)


if __name__ == '__main__':
	db.create_all()
	manager.run()

