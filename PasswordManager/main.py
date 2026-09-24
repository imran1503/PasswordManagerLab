class PasswordEntry:
    def __init__(self, name, username, password, url):
        self.name = name
        self.username = username
        self.password = password
        self.url = url

entry = PasswordEntry(
    "GitHub",
    "test@example.com",
    "FakePassword123!",
    "https://github.com"
)

print(entry.name)
print(entry.username)