from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, SubmitField, TextAreaField, RadioField
from wtforms.validators import DataRequired, Length


class FileForm(FlaskForm):
	file = FileField('Upload a file to Encrypt', validators=[DataRequired()])
	file_name = StringField('Title', validators=[DataRequired()])
	enc_key = StringField('Encryption Key', validators=[DataRequired(), Length(min=4, max=20)])
	e_choice = RadioField('', choices = [('Y','Encrypt File Now'),('N','Do It Later')], validators=[DataRequired()])
	submit = SubmitField('Upload')
	
class EncFileForm(FlaskForm):
	enc_key = StringField('Encryption Key', validators=[DataRequired(), Length(min=4, max=20)])
	submit = SubmitField('Proceed')