import pymongo

myclient = pymongo.MongoClient("mongodb://localhost:27017/")
mydb = myclient["logs"]
mycol = mydb["log_store"]
dist_store = mycol.distinct('Store')
