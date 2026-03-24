export class StorageHelper {
	private storage: DurableObjectStorage;

	constructor(storage: DurableObjectStorage) {
		this.storage = storage;
	}

	async getApiBaseUrlIndex(): Promise<number> {
		return (await this.storage.get<number>('apiBaseUrlIndex')) || 0;
	}

	async setApiBaseUrlIndex(index: number): Promise<void> {
		await this.storage.put('apiBaseUrlIndex', index);
	}

	async get<T>(key: string): Promise<T | undefined> {
		return await this.storage.get<T>(key);
	}

	async put<T>(key: string, value: T): Promise<void> {
		await this.storage.put(key, value);
	}
}
