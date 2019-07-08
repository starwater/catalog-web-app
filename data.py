from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Category, Base, Category_Item

engine = create_engine('sqlite:///categories.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Category
category1 = Category(name="Arts,Crafts & Sewing")
session.add(category1)
session.commit()

category2 = Category(name="Bathroom Products")
session.add(category2)
session.commit()

category3 = Category(name="Bowling")
session.add(category3)
session.commit()

category4 = Category(name="Camping & Hiking")
session.add(category4)
session.commit()

category5 = Category(name="Computer Cleaners")
session.add(category5)
session.commit()

category6 = Category(name="Computer Cables & Connectors")
session.add(category6)
session.commit()

category7 = Category(name="Computer Peripherals")
session.add(category7)
session.commit()

category8 = Category(name="Computer Components")
session.add(category8)
session.commit()

category9 = Category(name="Demo Board & Accessories")
session.add(category9)
session.commit()

category10 = Category(name="Desktops")
session.add(category10)
session.commit()

# category1
category_item1 = Category_Item(name="buckle",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category1)
session.add(category_item1)
session.commit()


category_item2 = Category_Item(name="gold",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category1)
session.add(category_item2)
session.commit()

category_item3 = Category_Item(name="gold",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category1)
session.add(category_item3)
session.commit()


# category2
category_item4 = Category_Item(name="bathtub",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category2)
session.add(category_item4)
session.commit()


category_item5 = Category_Item(name="bathcap",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category2)
session.add(category_item5)
session.commit()

category_item6 = Category_Item(name="bathcurtain",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category2)
session.add(category_item6)
session.commit()


# category3
category_item7 = Category_Item(name="bowling ball",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category3)
session.add(category_item7)
session.commit()


category_item8 = Category_Item(name="game",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category3)
session.add(category_item8)
session.commit()

category_item9 = Category_Item(name="toys",
                               description="Juicy grilled veggie "
                                           "patty with tomato "
                                           "mayo and lettuce",
                               Category=category3)
session.add(category_item9)
session.commit()


# category4
category_item10 = Category_Item(name="bottle bag",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category4)
session.add(category_item10)
session.commit()


category_item11 = Category_Item(name="airbag",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category4)
session.add(category_item11)
session.commit()

category_item12 = Category_Item(name="air mattress",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category4)
session.add(category_item12)
session.commit()


# category5
category_item13 = Category_Item(name="cord",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category5)
session.add(category_item13)
session.commit()


category_item14 = Category_Item(name="fire wire",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category5)
session.add(category_item14)
session.commit()

category_item15 = Category_Item(name="to usb",
                                description="Juicy grilled veggie "
                                            "patty with tomato mayo "
                                            "and lettuce",
                                Category=category5)
session.add(category_item15)
session.commit()


# category6
category_item16 = Category_Item(name="cleaner keyboard",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category6)
session.add(category_item16)
session.commit()


category_item17 = Category_Item(name="carbon filter",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category6)
session.add(category_item17)
session.commit()

category_item18 = Category_Item(name="brush cleaner",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category6)
session.add(category_item18)
session.commit()


# category7
category_item19 = Category_Item(name="motherboard",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category7)
session.add(category_item19)
session.commit()


category_item20 = Category_Item(name="humidifier",
                                description="Juicy grilled veggie "
                                            "patty with tomato "
                                            "mayo and lettuce",
                                Category=category7)
session.add(category_item20)
session.commit()

category_item21 = Category_Item(name="powersupply",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category7)
session.add(category_item21)
session.commit()


# category8
category_item22 = Category_Item(name="monitor",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category8)
session.add(category_item22)
session.commit()


category_item23 = Category_Item(name="hdmi port",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category8)
session.add(category_item23)
session.commit()

category_item24 = Category_Item(name="mousepad",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category8)
session.add(category_item24)
session.commit()


# category9
category_item25 = Category_Item(name="bike",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category9)
session.add(category_item25)
session.commit()


category_item26 = Category_Item(name="helmet",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category9)
session.add(category_item26)
session.commit()

category_item27 = Category_Item(name="hoverboard",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category9)
session.add(category_item27)
session.commit()


# category10
category_item28 = Category_Item(name="flower",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category10)
session.add(category_item28)
session.commit()


category_item29 = Category_Item(name="mask",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category10)
session.add(category_item29)
session.commit()

category_item30 = Category_Item(name="party diy",
                                description="Juicy grilled veggie patty "
                                            "with tomato mayo and lettuce",
                                Category=category10)
session.add(category_item30)
session.commit()

print("added menu items!")
