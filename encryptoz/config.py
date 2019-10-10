import os
from flask import current_app

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

class Config:
	SECRET_KEY = '5791628bb0b13ce0c676dfde280ba245'
	SQLALCHEMY_DATABASE_URI = 'sqlite:///encryptoz.db'
	MAIL_SERVER = 'smtp.googlemail.com'
	MAIL_PORT = 587
	MAIL_USE_TLS = True
	MAIL_USERNAME = 'testmailforme2019@gmail.com'
	MAIL_PASSWORD = '9161020000'
	UPLOAD_FOLDER = os.path.join(APP_ROOT, 'static\secure')
	ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'mp3', 'mp4', 'avi', 'mov', 'mkv','pptx'])
