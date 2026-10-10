interface PaginationProps {
  visible: number;
  total: number;
  hasPrevious: boolean;
  hasNext: boolean;
  loading: boolean;
  pageSize?: number;
  onPageSizeChange?(pageSize: number): void;
  onPrevious(): void;
  onNext(): void;
}

export function Pagination({ visible, total, hasPrevious, hasNext, loading, pageSize, onPageSizeChange, onPrevious, onNext }: PaginationProps) {
  return (
    <footer className="pagination" aria-label="Pagination">
      <span>Showing {visible} on this page · {total} matching</span>
      <div>
        {pageSize && onPageSizeChange && <label className="pagination__size"><span>Rows</span><select aria-label="Rows per page" value={pageSize} disabled={loading} onChange={(event) => onPageSizeChange(Number(event.target.value))}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option></select></label>}
        <button className="button button--secondary" type="button" disabled={!hasPrevious || loading} onClick={onPrevious}>Previous</button>
        <button className="button button--secondary" type="button" disabled={!hasNext || loading} onClick={onNext}>Next</button>
      </div>
    </footer>
  );
}
