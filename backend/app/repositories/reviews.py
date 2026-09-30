"""Review persistence operations."""

from sqlalchemy.orm import Session
from app.models.review import Review


class ReviewRepository:
    def __init__(self, session: Session) -> None:
        self.session = session

    def add(self, review: Review) -> Review:
        self.session.add(review)
        self.session.commit()
        self.session.refresh(review)
        return review
