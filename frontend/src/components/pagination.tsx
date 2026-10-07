interface PaginationProps {
  visible: number;
  total: number;
  hasPrevious: boolean;
  hasNext: boolean;
  loading: boolean;
  onPrevious(): void;
  onNext(): void;
}

export function Pagination({ visible, total, hasPrevious, hasNext, loading, onPrevious, onNext }: PaginationProps) {
  return (
    <footer className="pagination" aria-label="Pagination">
      <span>Showing {visible} on this page · {total} matching</span>
      <div>
        <button className="button button--secondary" type="button" disabled={!hasPrevious || loading} onClick={onPrevious}>Previous</button>
        <button className="button button--secondary" type="button" disabled={!hasNext || loading} onClick={onNext}>Next</button>
      </div>
    </footer>
  );
}
