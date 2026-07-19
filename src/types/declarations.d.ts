declare module '*.html' {
	const content: string;
	export default content;
}

declare module 'cookie' {
	export function parse(str: string, options?: any): Record<string, string>;
	export function serialize(name: string, val: string, options?: any): string;
}
