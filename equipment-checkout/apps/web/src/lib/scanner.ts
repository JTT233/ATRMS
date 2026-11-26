import { BrowserMultiFormatReader } from '@zxing/browser';

type NativeResult = { rawValue: string };
type NativeDetector = { detect: (source: CanvasImageSource) => Promise<NativeResult[]> };

export function hasNativeScanner(): boolean {
  return typeof (globalThis as unknown as { BarcodeDetector?: unknown }).BarcodeDetector === 'function';
}

export async function scanQrOnce(video: HTMLVideoElement): Promise<string> {
  const Ctor = (globalThis as unknown as {
    BarcodeDetector?: new (options: { formats: string[] }) => NativeDetector;
  }).BarcodeDetector;

  if (Ctor) {
    const detector = new Ctor({ formats: ['qr_code'] });
    const results = await detector.detect(video);
    if (results.length > 0) return results[0].rawValue;
  }

  const reader = new BrowserMultiFormatReader();
  const result = await reader.decodeOnceFromVideoDevice(undefined, video);
  return result.getText();
}
