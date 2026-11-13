/**
 * Device — represents one of Alice's machines (laptop, phone, kiosk, etc.).
 *
 * Owns:
 *   • a `HeadlessIdentityStorage`     — local persistent state
 *   • a `Signer` (when provisioned)   — the in-memory crypto handle
 *   • a reference to the shared MufflerHost — its publishing target
 *
 * Surface:
 *   • provision() — first-time setup; mints a new Signer + persists
 *   • hydrate()   — load an existing identity from storage on app boot
 *   • adopt(bundle) — import an exportBundle() from another device
 *   • exportBundle() — produce a portable bundle for another device
 *   • publish(body) — sign + post a kash.social.post to Muffler
 *
 * The split between provision/hydrate/adopt matches what a real client app
 * does on boot: first-time → provision, returning user → hydrate, second
 * device of returning user → adopt.
 */

import { Signer } from "@kashscript/identity-core/signer";
import type { KashSocialPostBody } from "@kashscript/lexicons/extensions/social";

// GAP-004 closed — HeadlessIdentityStorage now ships in identity-sdk itself.
import { HeadlessIdentityStorage, type IdentityBundle } from "@kashscript/identity-sdk/storage-adapter";

import { InduslandConsumer } from "../../muffler-ingest/fixture/consumer";
import type { MufflerHost, MufflerIngestResult } from "../../muffler-ingest/fixture/muffler-stub";

export interface DeviceConfig {
  /** Display label for diagnostics (e.g., "laptop", "phone"). */
  readonly label: string;
}

export class Device {
  readonly label: string;
  readonly storage = new HeadlessIdentityStorage();
  private signer: Signer | null = null;
  private consumer: InduslandConsumer | null = null;

  constructor(
    private readonly host: MufflerHost,
    cfg: DeviceConfig,
  ) {
    this.label = cfg.label;
  }

  /**
   * First-time provisioning. Mints a new Signer, persists the public envelope
   * + the private JWK, and wires the consumer client.
   *
   * Real apps: this is the WebAuthn registration ceremony, AFTER which the
   * Passkey reference goes into IndexedDB. The use-case test substitutes a
   * direct in-memory generate() since headless Bun can't run WebAuthn.
   */
  async provision(handle?: string): Promise<void> {
    if (this.signer) {
      throw new Error(`${this.label}: already provisioned (DID ${this.signer.did}).`);
    }
    this.signer = await Signer.generate();
    const jwk = this.signer.exportJwk();
    // `credentialId` is a WebAuthn artefact. Headless has no Passkey; we
    // synthesise a deterministic stand-in from the pubkey so the storage
    // envelope still has the field. A real Node-side adapter would leave
    // this empty / opt out of the field entirely.
    const credentialId = new Uint8Array(this.signer.publicKey); // copy
    this.storage.write(
      {
        did:          this.signer.did,
        publicKey:    this.signer.publicKey,
        credentialId,
        ...(handle !== undefined ? { handle } : {}),
      },
      jwk,
      handle,
    );
    this.consumer = new InduslandConsumer(this.signer, this.host);
  }

  /**
   * Returning-user load. Reads the JWK out of storage, rebuilds the Signer
   * — should produce the SAME DID as the original provisioning device.
   */
  async hydrate(): Promise<void> {
    const jwk = this.storage.readKeyJwk();
    if (!jwk) throw new Error(`${this.label}: no identity in storage to hydrate.`);
    this.signer = await Signer.fromJwk(jwk);
    this.consumer = new InduslandConsumer(this.signer, this.host);
  }

  /**
   * Adopt an exportBundle() from another device. The new device now holds
   * the same identity. Wires the Signer + consumer.
   */
  async adopt(bundle: IdentityBundle): Promise<void> {
    this.storage.importBundle(bundle);
    await this.hydrate();
  }

  /** Whether the device is ready to publish. */
  get isProvisioned(): boolean {
    return this.signer !== null;
  }

  /** The device's DID — proves identity continuity across devices in tests. */
  get did(): string {
    if (!this.signer) throw new Error(`${this.label}: not yet provisioned.`);
    return this.signer.did;
  }

  /** The device's raw public key — for byte-equality assertions in tests. */
  get publicKey(): Uint8Array {
    if (!this.signer) throw new Error(`${this.label}: not yet provisioned.`);
    return this.signer.publicKey;
  }

  /** Publish a kash.social.post via the consumer. */
  async publishPost(body: KashSocialPostBody): Promise<MufflerIngestResult> {
    if (!this.consumer) throw new Error(`${this.label}: not yet provisioned.`);
    return await this.consumer.publishPost(body);
  }

  /** Sign-out / device reset. */
  signOut(): void {
    this.signer = null;
    this.consumer = null;
    this.storage.clear();
  }
}
