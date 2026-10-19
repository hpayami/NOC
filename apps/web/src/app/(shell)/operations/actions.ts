'use server';

import { revalidatePath } from 'next/cache';
import {
  CreateNotificationChannelRequest,
  NotificationChannel,
  NotificationDelivery,
} from '@noc/shared';
import { ApiError, apiFetch } from '@/lib/api';

export type CreateChannelState = { created: string } | { error: string } | null;
export type ChannelActionState =
  { delivery: NotificationDelivery } | { enabled: boolean } | { error: string } | null;

export async function createChannel(
  _prev: CreateChannelState,
  formData: FormData,
): Promise<CreateChannelState> {
  const kind = formData.get('kind') === 'email' ? 'email' : 'webhook';
  const str = (k: string) => String(formData.get(k) ?? '').trim();
  const parsed = CreateNotificationChannelRequest.safeParse(
    kind === 'email'
      ? {
          kind,
          name: str('name'),
          minSeverity: formData.get('minSeverity') ?? undefined,
          enabled: true,
          email: {
            host: str('host'),
            port: Number(str('port') || 587),
            starttls: formData.get('starttls') === 'on',
            username: str('username') || null,
            from: str('from'),
            recipients: str('recipients')
              .split(/[,\s;]+/)
              .map((r) => r.trim())
              .filter(Boolean),
          },
          password: str('password') || null,
        }
      : {
          kind,
          name: str('name'),
          url: str('url'),
          secret: str('secret'),
          minSeverity: formData.get('minSeverity') ?? undefined,
          enabled: true,
        },
  );
  if (!parsed.success) return { error: parsed.error.issues[0]?.message ?? 'invalid' };
  try {
    const ch = await apiFetch('/api/v1/operations/channels', NotificationChannel, {
      method: 'POST',
      body: JSON.stringify(parsed.data),
    });
    revalidatePath('/operations');
    return { created: ch.id };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}

export async function testChannel(
  _prev: ChannelActionState,
  formData: FormData,
): Promise<ChannelActionState> {
  const id = String(formData.get('id') ?? '');
  if (!/^[0-9a-f-]{36}$/.test(id)) return { error: 'invalid channel id' };
  try {
    const delivery = await apiFetch(
      `/api/v1/operations/channels/${id}/test`,
      NotificationDelivery,
      { method: 'POST' },
    );
    revalidatePath('/operations');
    return { delivery };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}

export async function setChannelEnabled(
  _prev: ChannelActionState,
  formData: FormData,
): Promise<ChannelActionState> {
  const id = String(formData.get('id') ?? '');
  const enabled = formData.get('enabled') === 'true';
  if (!/^[0-9a-f-]{36}$/.test(id)) return { error: 'invalid channel id' };
  try {
    const ch = await apiFetch(`/api/v1/operations/channels/${id}`, NotificationChannel, {
      method: 'PATCH',
      body: JSON.stringify({ enabled }),
    });
    revalidatePath('/operations');
    return { enabled: ch.enabled };
  } catch (e) {
    if (e instanceof ApiError) return { error: `${e.code}: ${e.message}` };
    throw e;
  }
}
