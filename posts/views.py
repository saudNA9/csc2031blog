from flask import Blueprint, render_template,flash, url_for, redirect
from flask_login import current_user
from config import db, Post
from posts.forms import PostForm
from sqlalchemy import desc

# Define the blueprint
posts_bp = Blueprint('posts', __name__, template_folder='templates')

# Define routes under this blueprint
@posts_bp.route('/posts')
def posts():
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

from flask_login import login_required, current_user

@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    form = PostForm()
    if form.validate_on_submit():
        print(f"Logged-in User ID: {current_user.id}, User Email: {current_user.email}")
        new_post = Post(title=form.title.data, body=form.body.data, userid=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        flash('Post created successfully!', category='success')
        return redirect(url_for('posts.posts'))
    return render_template('posts/create.html', form=form)

@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
def update(id):

    post_to_update = Post.query.filter_by(id=id).first()

    if not post_to_update:
        return redirect(url_for('posts.posts'))

    form = PostForm()

    if form.validate_on_submit():
        post_to_update.update(title=form.title.data, body=form.body.data)

        flash('Post updated', category='success')
        return redirect(url_for('posts.posts'))

    form.title.data = post_to_update.title
    form.body.data = post_to_update.body

    return render_template('posts/update.html', form=form)

@posts_bp.route('/<int:id>/delete')
def delete(id):
    Post.query.filter_by(id=id).delete()
    db.session.commit()

    flash('Post deleted', category='success')
    return redirect(url_for('posts.posts'))
