import axios from 'axios';
import { PriceFeed, PriceHistory } from '../price-updater';

export default class CoingeckoApi implements PriceFeed {
  public name: string = 'Coingecko';
  public url: string = 'https://api.coingecko.com/api/v3/simple/price?ids=catcoin&vs_currencies=usd,eur,gbp,aud,jpy';
  public urlHist: string = '';
  public currencies: string[] = ['USD', 'EUR', 'GBP', 'AUD', 'JPY'];

  private lastFetchMs = 0;
  private cached: Record<string, number> | null = null;

  private async fetchLatest(): Promise<Record<string, number>> {
    const response = await axios.get(this.url, { timeout: 10000 });
    const data = response?.data?.catcoin || {};
    return {
      USD: data.usd ?? -1,
      EUR: data.eur ?? -1,
      GBP: data.gbp ?? -1,
      AUD: data.aud ?? -1,
      JPY: data.jpy ?? -1,
    };
  }

  public async $fetchPrice(currency: string): Promise<number> {
    const now = Date.now();
    if (!this.cached || (now - this.lastFetchMs) > 60_000) {
      this.cached = await this.fetchLatest();
      this.lastFetchMs = now;
    }
    return this.cached[currency] ?? -1;
  }

  public async $fetchRecentPrice(_currencies: string[], _type: string): Promise<PriceHistory> {
    return {};
  }
}
