import os

from flask import (render_template, url_for, flash,
                   redirect, request, abort, Blueprint, send_from_directory, current_app)
from flask_login import current_user, login_required
from encryptoz import db
from encryptoz.models import Files
from encryptoz.files.forms import FileForm, EncFileForm
from werkzeug import secure_filename
from encryptoz.files.utils import encrypt_file, decrypt_file

files = Blueprint('files', __name__)



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']
		   
@files.route('/file/<int:file_id>')
@login_required
def view_file(file_id):
	file = Files.query.get_or_404(file_id)

	return send_from_directory(current_app.config['UPLOAD_FOLDER'], file.file_name)

@files.route("/file/new", methods=['GET', 'POST'])
@login_required
def new_file():
	form = FileForm()
	if form.validate_on_submit():
		if request.method == 'POST':
			
			if not form.file.data :
				flash('No File Part', 'danger')
				return redirect(url_for('files.new_file'))
			filename = form.file.data.filename
			if filename== '':
				flash('No selected file' , 'warning')
				return redirect(url_for('files.new_file'))
			if filename and allowed_file(filename):
				fname = form.file_name.data + '.' + str(filename.rsplit('.', 1)[1].lower())
				filename = secure_filename(fname)
				f_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
				file_path = form.file.data.save(f_path)
		enc_stat = 0		
		if form.e_choice.data == 'Y':
			enc_stat = encrypt_file(filename, f_path, form.enc_key.data)
		filedata = Files(file_name=filename, file_path = 'secure', enc_key=form.enc_key.data, encrypt=enc_stat, author=current_user)
		db.session.add(filedata)
		db.session.commit()
		flash('Your File is Uploaded !', 'success')
		return redirect(url_for('files.all_files'))
	return render_template('add_file.html', title='Add New File',
						   form=form, legend='New File')

@files.route("/file/<int:file_id>/encrypt", methods=['GET', 'POST'])
@login_required
def enc_files(file_id):
	file = Files.query.get_or_404(file_id)
	if file.author != current_user:
		abort(403)

	form = EncFileForm()
	if form.validate_on_submit():
		enc_stat = 0
		if form.enc_key.data:
			file.enc_key = form.enc_key.data
			filename = file.file_name
			f_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
			enc_stat = encrypt_file(filename, f_path, file.enc_key)
			file.encrypt = enc_stat
			db.session.commit()
			flash('Your File has been Encrypted!', 'success')
			return redirect(url_for('files.all_files'))
		else:
			flash('Invalid Encryption Key!', 'danger')
			return render_template('file.html', title='Encrypt File', form=form, legend='Encrypt File' )
	elif request.method == 'GET':
		form.enc_key.data = file.enc_key
	return render_template('file.html', title='Encrypt File',
                           form=form, legend='Encrypt File' )


@files.route("/file/<int:file_id>/decrypt", methods=['GET', 'POST'])
@login_required
def dec_files(file_id):
	file = Files.query.get_or_404(file_id)
	if file.author != current_user:
		abort(403)

	form = EncFileForm()
	if form.validate_on_submit():
		
		if form.enc_key.data == file.enc_key and file.encrypt == 1:
			filename = file.file_name + '.cursed'
			f_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
			enc_stat = decrypt_file(filename, f_path, file.enc_key)
			file.encrypt = enc_stat
			db.session.commit()
			flash('Your file has been Decrypted!', 'success')
			return redirect(url_for('files.all_files'))
		else:
			flash('Invalid Encryption Key!', 'danger')
			return render_template('file.html', title='Decrypt File', form=form, legend='Decrypt File' )
	return render_template('file.html', title='Decrypt File',
                           form=form, legend='Decrypt File' )
		
@files.route("/all_files")
@login_required
def all_files():
	page = request.args.get('page', 1, type=int)
	files = Files.query.order_by(Files.date_created.desc()).paginate(page=page, per_page=5)
	return render_template('all_files.html', title='All Files', files=files)
	

@files.route("/file/<int:file_id>/delete", methods=['GET', 'POST'])
@login_required
def del_file(file_id):
	file = Files.query.get_or_404(file_id) 
	if file.author != current_user:
		abort(403)
	form = EncFileForm()
	if form.validate_on_submit():
		if form.enc_key.data == file.enc_key and file.encrypt == 1:
			
			filename = file.file_name + '.cursed'
			f_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
			os.remove(f_path)
		elif form.enc_key.data == file.enc_key and file.encrypt == 0:
			
			filename = file.file_name
			f_path = os.path.join(current_app.config['UPLOAD_FOLDER'], filename)
			os.remove(f_path)
		else:
			flash('Invalid Encryption Key!', 'danger')
			return render_template('file.html', title='Delete File', form=form, legend='Delete File' )
		db.session.delete(file)
		db.session.commit()
		flash('Your file has been deleted!', 'success')
		return redirect(url_for('files.all_files'))
	return render_template('file.html', title='Delete File',
                           form=form, legend='Delete File' )
			
			
	
	
	
	
