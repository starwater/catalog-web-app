import sys

# Configuration
# handy function for writing mapper code
from sqlalchemy import Column, ForeignKey, Integer, String
# use in configuration and class code
from sqlalchemy.ext.declarative import declarative_base
# use to create key relationship
from sqlalchemy.orm import relationship
# use at the end of the configuration file
from sqlalchemy import create_engine

Base = declarative_base()


class Category(Base):
    __tablename__ = 'category'
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)


class Category_Item(Base):
    __tablename__ = 'category_item'
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    author_id = Column(Integer, ForeignKey('user.id'))
    Category = relationship('Category')
    User = relationship('User')

    @property
    def serialize(self):
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,

        }


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(80), nullable=False)
    password = Column(String(16), nullable=False)
    email = Column(String(30))


# crate instace of create_engine class and points
# to the database that we will use
# it will create a new file similarly to a robust
# database like mysql, postgre
engine = create_engine('sqlite:///categories.db')
# goes into the database and add the class we will
# soon create as new tables in our database
Base.metadata.create_all(engine)

# print("database setup finished")
