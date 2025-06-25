import { Injectable, signal } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class LoadingService {
  private _isLoading = signal<boolean>(false);
  private _loadingCount = signal<number>(0);

  // Public readonly signal
  readonly isLoading = this._isLoading.asReadonly();

  /**
   * Start loading
   */
  start(): void {
    const count = this._loadingCount() + 1;
    this._loadingCount.set(count);
    this._isLoading.set(true);
  }

  /**
   * Stop loading
   */
  stop(): void {
    const count = Math.max(0, this._loadingCount() - 1);
    this._loadingCount.set(count);

    if (count === 0) {
      this._isLoading.set(false);
    }
  }

  /**
   * Force stop all loading
   */
  forceStop(): void {
    this._loadingCount.set(0);
    this._isLoading.set(false);
  }
}
