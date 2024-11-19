from flask import Blueprint, render_template, flash, url_for, redirect, request, abort
from flask_login import login_required, current_user
from config import db, Post
from posts.forms import PostForm
from sqlalchemy import desc

posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/posts')
@login_required
def posts():
    if current_user.role in ['db_admin', 'sec_admin']:
        flash("You are not authorized to view posts.", "danger")
        return redirect(url_for('accounts.forbidden_error_page', error='Access Denied'))
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if current_user.role in ['db_admin', 'sec_admin']:
        flash("You are not authorized to create posts.", "danger")
        return redirect(url_for('accounts.forbidden_error_page', error='Access Denied'))
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(title=form.title.data, body=form.body.data, userid=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', category='success')
        return redirect(url_for('posts.posts'))
    return render_template('posts/create.html', form=form)

@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    post_to_update = Post.query.filter_by(id=id).first()
    if not post_to_update or post_to_update.userid != current_user.id:
        abort(403)

    form = PostForm()
    if form.validate_on_submit():
        post_to_update.update(title=form.title.data, body=form.body.data)
        db.session.commit()
        flash('Post updated', category='success')
        return redirect(url_for('posts.posts'))

    form.title.data = post_to_update.title
    form.body.data = post_to_update.body
    return render_template('posts/update.html', form=form)

@posts_bp.route('/<int:id>/delete')
@login_required
def delete(id):
    post_to_delete = Post.query.filter_by(id=id).first()

    if not post_to_delete or post_to_delete.userid != current_user.id:
        flash("You are not authorized to delete this post.", "danger")
        return redirect(url_for('accounts.forbidden_error_page', error='Access Denied'))

    db.session.delete(post_to_delete)
    db.session.commit()
    flash("Post deleted successfully.", "success")
    return redirect(url_for('posts.posts'))
