/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The API URL is read at runtime via process.env in Server Components,
  // so no build-time env wiring is needed beyond NEXT_PUBLIC_API_URL.
};

module.exports = nextConfig;
