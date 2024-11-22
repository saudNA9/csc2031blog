from flask import Blueprint, render_template, flash, url_for, redirect, request, abort
from flask_login import login_required, current_user
from config import db, Post, security_logger
from posts.forms import PostForm
from sqlalchemy import desc

posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/posts')
@login_required
def posts():
    if current_user.role in ['db_admin', 'sec_admin']:
        abort(403)
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if current_user.role in ['db_admin', 'sec_admin']:
        abort(403)
    form = PostForm()
    if form.validate_on_submit():
        new_post = Post(title=form.title.data, body=form.body.data, userid=current_user.id)
        db.session.add(new_post)
        db.session.commit()
        security_logger.info(
            f"Post creation: Email={current_user.email}, Role={current_user.role}, PostID={new_post.id}, IP={request.remote_addr}")
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
        security_logger.info(
            f"Post update: Email={current_user.email}, Role={current_user.role}, PostID={post_to_update.id}, AuthorEmail={post_to_update.user.email}, IP={request.remote_addr}")
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
        abort(403)

    db.session.delete(post_to_delete)
    db.session.commit()
    security_logger.info(
        f"Post deletion: Email={current_user.email}, Role={current_user.role}, PostID={post_to_delete.id}, AuthorEmail={post_to_delete.user.email}, IP={request.remote_addr}")
    flash("Post deleted successfully.", "success")
    return redirect(url_for('posts.posts'))
