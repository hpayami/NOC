import { redirect } from 'next/navigation';
import { getAccessToken } from '@/lib/session';

export default async function Index() {
  redirect((await getAccessToken()) ? '/command-center' : '/login');
}
