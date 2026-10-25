import { Search, X } from 'lucide-react';

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  className?: string;
  label?: string;
}

export function SearchInput({ value, onChange, placeholder = 'Search…', className = '', label = 'Search' }: Props) {
  return (
    <div className={`relative ${className}`}>
      <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-sx-mute" aria-hidden />
      <input
        className="input pl-8 pr-7"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        aria-label={label}
      />
      {value && (
        <button className="absolute right-1.5 top-1/2 -translate-y-1/2 rounded p-1 text-sx-mute hover:text-sx-ink" onClick={() => onChange('')} aria-label="Clear search">
          <X className="h-3 w-3" />
        </button>
      )}
    </div>
  );
}
