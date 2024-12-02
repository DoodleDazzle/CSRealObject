from flask_sqlalchemy import SQLAlchemy

# Initialize the database object (don't forget this in server.py too)
db = SQLAlchemy()

class FileMetadata(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(100), nullable=False)
    file_url = db.Column(db.String(300), nullable=False)

    def __repr__(self):
        return f'<FileMetadata {self.filename}>'
