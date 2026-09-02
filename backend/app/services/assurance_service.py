from __future__ import annotations
import csv, io, json, math, re, zipfile
from pathlib import Path
from statistics import mean, pstdev


def _safe_text(data: bytes, limit: int = 2 * 1024 * 1024) -> str:
    return data[:limit].decode('utf-8', errors='ignore')


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts if c)


def dataset_assurance(filename: str, mime_type: str, data: bytes) -> dict:
    suffix = Path(filename).suffix.lower()
    indicators: list[str] = []
    warnings: list[str] = []
    score = 0.0
    format_name = 'generic artifact'
    sample = data[:2 * 1024 * 1024]

    magic = {
        '.png': data.startswith(b'\x89PNG\r\n\x1a\n'),
        '.jpg': data.startswith(b'\xff\xd8\xff'), '.jpeg': data.startswith(b'\xff\xd8\xff'),
        '.gif': data.startswith(b'GIF87a') or data.startswith(b'GIF89a'),
        '.bmp': data.startswith(b'BM'), '.webp': data.startswith(b'RIFF') and data[8:12] == b'WEBP',
    }
    if suffix in magic and not magic[suffix]:
        score += 0.45; warnings.append('File signature does not match its extension')

    if suffix in {'.csv', '.tsv'}:
        format_name = 'tabular dataset'
        text = _safe_text(sample)
        rows = list(csv.reader(io.StringIO(text), delimiter='\t' if suffix == '.tsv' else ','))
        nonempty = [r for r in rows if any(c.strip() for c in r)]
        if len(nonempty) >= 2:
            widths = [len(r) for r in nonempty[:500]]
            if len(set(widths)) > 1:
                score += 0.18; warnings.append('Inconsistent row structure detected')
            else:
                indicators.append(f'{len(nonempty)} tabular rows sampled')
        else:
            score += 0.20; warnings.append('Insufficient tabular structure')

    elif suffix == '.json':
        format_name = 'JSON dataset / annotation candidate'
        try:
            obj = json.loads(_safe_text(data, 8 * 1024 * 1024))
            if isinstance(obj, dict) and isinstance(obj.get('images'), list) and isinstance(obj.get('annotations'), list):
                format_name = 'COCO-style annotation dataset'
                indicators.append(f"COCO candidates: {len(obj['images'])} images, {len(obj['annotations'])} annotations")
                image_ids = {x.get('id') for x in obj['images'] if isinstance(x, dict)}
                bad = sum(1 for x in obj['annotations'] if isinstance(x, dict) and x.get('image_id') not in image_ids)
                if bad:
                    score += min(0.45, 0.05 + bad / max(1, len(obj['annotations']))); warnings.append(f'{bad} annotations reference missing image IDs')
            elif isinstance(obj, dict):
                indicators.append('Valid JSON structure detected')
            else:
                indicators.append('Valid JSON document detected')
        except Exception:
            score += 0.25; warnings.append('JSON extension but content is not valid JSON')

    elif suffix in {'.txt'}:
        lines = [x.strip() for x in _safe_text(sample).splitlines() if x.strip()]
        if lines and all(len(x.split()) == 5 for x in lines[:500]):
            format_name = 'YOLO label dataset'
            indicators.append(f'{len(lines)} YOLO-style label rows sampled')
            bad = 0
            for line in lines[:500]:
                try:
                    vals = list(map(float, line.split()[1:]))
                    if not all(0 <= v <= 1 for v in vals): bad += 1
                except ValueError: bad += 1
            if bad:
                score += 0.35; warnings.append(f'{bad} sampled YOLO rows contain out-of-range coordinates')

    elif suffix in {'.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp'} or (mime_type or '').startswith('image/'):
        format_name = 'image artifact'
        if len(data) < 256: score += 0.20; warnings.append('Image artifact is unusually small')
        indicators.append('Image file signature inspected without decoding/executing content')

    if suffix in {'.zip', '.gz', '.tar'} or data.startswith(b'PK'):
        format_name = 'compressed dataset/archive candidate'
        try:
            if data.startswith(b'PK'):
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    names = z.namelist()
                    suspicious = [n for n in names if Path(n).suffix.lower() in {'.exe','.dll','.scr','.bat','.cmd','.ps1','.vbs'}]
                    indicators.append(f'Archive contains {len(names)} entries')
                    if suspicious:
                        score += 0.45; warnings.append(f'{len(suspicious)} executable/script-like archive entries found')
                    if any(n.startswith('/') or '..' in Path(n).parts for n in names):
                        score += 0.25; warnings.append('Unsafe archive path pattern detected')
        except zipfile.BadZipFile:
            score += 0.30; warnings.append('Archive signature is invalid or unreadable')

    entropy = _entropy(sample[:65536])
    if len(sample) >= 4096 and entropy > 7.85:
        score += 0.08; indicators.append('High byte entropy observed; compressed/encrypted content may be present')

    text = _safe_text(sample).lower()
    suspicious = ['powershell -enc', 'invoke-expression', 'downloadstring(', 'wscript.shell', 'cmd.exe /c', 'certutil -decode']
    hits = [x for x in suspicious if x in text]
    if hits:
        score += min(0.55, 0.18 * len(hits)); warnings.append(f'{len(hits)} suspicious script/content indicators found')

    lines = [x.strip() for x in text.splitlines() if x.strip()]
    if len(lines) >= 20:
        unique = len(set(lines)) / len(lines)
        if unique < 0.35:
            score += 0.15; warnings.append('High exact-duplicate rate in sampled text records')

    return {
        'format': format_name,
        'anomaly_score': round(min(1.0, score), 3),
        'indicators': indicators,
        'warnings': warnings,
        'sample_bytes': len(sample),
        'execution_performed': False,
    }


def model_assurance(filename: str, data: bytes) -> dict:
    suffix = Path(filename).suffix.lower()
    supported = suffix in {'.onnx', '.pt', '.pth', '.torchscript', '.ts', '.bin'}
    indicators = []
    warnings = []
    score = 0.0
    if supported: indicators.append(f'Supported model artifact format: {suffix}')
    else: score += 0.25; warnings.append('Unrecognized model artifact extension')
    if len(data) < 128: score += 0.35; warnings.append('Artifact is unusually small')
    if data.startswith(b'\x80\x04') or data.startswith(b'\x80\x05'):
        score += 0.25; warnings.append('Python pickle-like header observed; untrusted deserialization is prohibited')
    if data.startswith(b'PK'): indicators.append('Container/ZIP signature observed')
    if data.startswith(b'\x08\x00\x00\x00') and suffix == '.onnx': indicators.append('ONNX-like protobuf header pattern observed')
    entropy = _entropy(data[:65536])
    if entropy > 7.9: indicators.append('High artifact entropy observed')
    return {'anomaly_score': round(min(1.0, score), 3), 'indicators': indicators, 'warnings': warnings, 'execution_performed': False}


def distribution_shift(baseline: list[float], current: list[float]) -> dict:
    if not baseline or not current:
        raise ValueError('baseline and current feature arrays must be non-empty')
    b = [float(x) for x in baseline]; c = [float(x) for x in current]
    bm, cm = mean(b), mean(c)
    bs, cs = pstdev(b), pstdev(c)
    mean_delta = abs(cm - bm) / max(abs(bm), 1e-9)
    std_delta = abs(cs - bs) / max(bs, 1e-9)
    # Robust normalized drift score for an offline prototype.
    score = min(1.0, 0.6 * min(1.0, mean_delta) + 0.4 * min(1.0, std_delta))
    level = 'LOW' if score < .25 else 'MEDIUM' if score < .5 else 'HIGH' if score < .75 else 'CRITICAL'
    return {'shift_score': round(score, 4), 'shift_level': level, 'baseline_mean': round(bm, 6), 'current_mean': round(cm, 6), 'baseline_std': round(bs, 6), 'current_std': round(cs, 6), 'sample_sizes': {'baseline': len(b), 'current': len(c)}}
