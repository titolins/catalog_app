from flask.ext.wtf import Form

from wtforms import (
    TextField,
    TextAreaField,
    validators,
    SubmitField,
    ValidationError
)

from flask_wtf.file import FileField, FileAllowed, FileRequired

from sqlalchemy import func

from catalog_app import session

from database_setup import Category


class Unique(object):
    """ Validator to check uniqueness """
    def __init__(self, model, field, message=None):
        self.model = model
        self.field = field
        if not message:
            message = 'Object already exists on the database.'
        self.message = message

    def __call__(self, form, field):
        object = session.query(self.model).filter(
            func.lower(self.field) == func.lower(field.data)).first()
        if object:
            raise ValidationError(self.message)


class NewItem(Form):
    title = TextField('Title', [validators.Length(min=4, max=50)])
    description = TextAreaField(
        'Description',
        [validators.Length(min=10, max=255)]
    )
    picture = FileField(
        'Picture',
        validators=[
            FileRequired(),
            FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'bmp'], 'Images only!')
        ]
    )
    add = SubmitField()


class EditItem(Form):
    title = TextField('Title')
    description = TextAreaField('Description')
    picture = FileField(
        'Picture',
        validators=[
            FileAllowed(['jpg', 'jpeg', 'png', 'gif', 'bmp'], 'Images only!')
        ]
    )
    edit = SubmitField()

    def validate(self):
        if (
                (not self.title.data) and
                (not self.description.data) and
                (not self.picture.data)):
            msg = 'At least one field must be edited'
            self.title.errors = (msg,)
            self.description.errors = (msg,)
            self.picture.errors = (msg,)
            return False
        # title validation
        if self.title.data:
            try:
                validate_title = validators.Length(min=4, max=50)
                validate_title(self, self.title)
            except:
                self.title.data = None
                self.title.errors = (
                    "Field must be between %d and %d characters long." %
                    (validate_title.min, validate_title.max),
                )
        # description validation
        if self.description.data:
            try:
                validate_description = validators.Length(min=10, max=255)
                validate_description(self, self.description)
            except:
                self.description.data = None
                self.description.errors = (
                    "Field must be between %d and %d characters long." %
                    (validate_description.min, validate_description.max),
                )
        # picture validation
        if self.picture.data:
            try:
                validate_picture = FileAllowed(
                    ['jpg', 'jpeg', 'png', 'gif', 'bmp'],
                    'Images only!'
                )
                validate_picture(self, self.picture)
            except:
                self.picture.data = None
                self.picture.errors = ("Only image files allowed!",)
        if self.title.errors or self.description.errors or self.picture.errors:
            return False
        return True


class CategoryForm(Form):
    title = TextField(
        'Title',
        validators=[
            validators.Length(min=3, max=24),
            Unique(
                Category,
                Category.title,
                "Category already exists")
        ]
    )
    create = SubmitField()
