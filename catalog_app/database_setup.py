from sqlalchemy import Column, ForeignKey, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from config.db import get_db_string

Base = declarative_base()


class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False, unique=True)
    picture = Column(String(250))

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'picture': self.picture,
        }


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    title = Column(String(50), nullable=False, unique=True)
    items = relationship("Item", backref="category")

    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'items': [i.serialize for i in self.items]
        }


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    title = Column(String(250), nullable=False)
    description = Column(String(500), nullable=False)
    picture = Column(String(250), nullable=False)
    category_id = Column(Integer, ForeignKey('category.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'picture': self.picture,
        }


if __name__ == '__main__':
    #engine = create_engine('sqlite:///catalog_app.db')
    engine = create_engine(get_db_string())
    Base.metadata.create_all(engine)
