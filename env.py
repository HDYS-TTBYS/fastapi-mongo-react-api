from decouple import config

CSRF_KEY = config("CSRF_KEY")
JWT_KEY = config("JWT_KEY")
ORIGINS = str(config("ORIGINS")).split(' ')
MONGO_API_KEY = config("MONGO_API_KEY")
ACCESS_TOKEN_KEY = str(config("ACCESS_TOKEN_KEY"))
