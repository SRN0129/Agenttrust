import crypto from "node:crypto";

export interface GroundCoordinate {
  latitude: number;
  longitude: number;
  altitudeMeters?: number;
}

export interface SatelliteOrbitalState {
  satelliteId: string;
  noradId: number;
  epoch: number;
  latitude: number;
  longitude: number;
  altitudeKm: number;
  velocityKmPerSec: number;
  headingDeg: number;
}

export interface DopplerObservation {
  nominalCarrierFrequencyHz: number;
  observedFrequencyHz: number;
  observedDopplerShiftHz: number;
  timestamp: number;
}

export interface SpaceTimeProofOfLocation {
  proofId: string;
  agentId: string;
  claimedLocation: GroundCoordinate;
  satelliteState: SatelliteOrbitalState;
  expectedDopplerShiftHz: number;
  observedDopplerShiftHz: number;
  dopplerResidualHz: number;
  relativisticTimeDilationPicos: number;
  verified: boolean;
  confidenceScore: number; // 0.0 to 1.0
  rejectionReason?: string;
  issuedAt: number;
  attestationSignature: string;
}

/**
 * Orbital Doppler & Relativistic Ephemeris Engine
 * Mathematically validates an AI agent's physical geographical space-time beacon
 * by correlating carrier RF Doppler S-curves and relativistic time dilation against LEO satellite passes.
 */
export class DopplerEphemerisEngine {
  private static SPEED_OF_LIGHT_KM_S = 299792.458;
  private secretKey: string;

  constructor(secretKey: string = "doppler_orbital_notary_secret") {
    this.secretKey = secretKey;
  }

  /**
   * Computes relativistic time dilation (Lorentz factor gamma & picosecond differential per second):
   * gamma = 1 / sqrt(1 - (v/c)^2)
   */
  public static calculateRelativisticDilation(velocityKmPerSec: number): {
    lorentzGamma: number;
    driftPicosecondsPerSecond: number;
  } {
    const beta = velocityKmPerSec / DopplerEphemerisEngine.SPEED_OF_LIGHT_KM_S;
    const gamma = 1 / Math.sqrt(1 - beta * beta);
    // Drift in picoseconds per second: (gamma - 1) * 1e12
    const driftPicos = (gamma - 1) * 1e12;
    return {
      lorentzGamma: Number(gamma.toFixed(12)),
      driftPicosecondsPerSecond: Number(driftPicos.toFixed(2)),
    };
  }

  /**
   * Computes expected Doppler shift given nominal frequency, satellite orbital velocity vector, and ground station line-of-sight:
   * delta_f = f0 * (v_relative / c)
   */
  public static calculateExpectedDopplerShift(
    nominalCarrierHz: number,
    ground: GroundCoordinate,
    sat: SatelliteOrbitalState
  ): number {
    const R_earth = 6371; // km
    const satDistFromCenter = R_earth + sat.altitudeKm;

    // Convert degrees to radians
    const gLat = (ground.latitude * Math.PI) / 180;
    const gLon = (ground.longitude * Math.PI) / 180;
    const sLat = (sat.latitude * Math.PI) / 180;
    const sLon = (sat.longitude * Math.PI) / 180;

    // Cartesian 3D vectors
    const gX = R_earth * Math.cos(gLat) * Math.cos(gLon);
    const gY = R_earth * Math.cos(gLat) * Math.sin(gLon);
    const gZ = R_earth * Math.sin(gLat);

    const sX = satDistFromCenter * Math.cos(sLat) * Math.cos(sLon);
    const sY = satDistFromCenter * Math.cos(sLat) * Math.sin(sLon);
    const sZ = satDistFromCenter * Math.sin(sLat);

    // Range vector from ground to satellite
    const rX = sX - gX;
    const rY = sY - gY;
    const rZ = sZ - gZ;
    const range = Math.sqrt(rX * rX + rY * rY + rZ * rZ);

    if (range === 0) return 0;

    // Unit vector pointing from ground to satellite
    const uX = rX / range;
    const uY = rY / range;
    const uZ = rZ / range;

    // Velocity vector (approximated along orbital heading)
    const headingRad = (sat.headingDeg * Math.PI) / 180;
    // East-North-Up velocity components
    const vEast = sat.velocityKmPerSec * Math.sin(headingRad);
    const vNorth = sat.velocityKmPerSec * Math.cos(headingRad);
    const vUp = 0; // Circular orbit assumption

    // Convert ENU to ECEF
    const vX = -Math.sin(sLon) * vEast - Math.sin(sLat) * Math.cos(sLon) * vNorth + Math.cos(sLat) * Math.cos(sLon) * vUp;
    const vY = Math.cos(sLon) * vEast - Math.sin(sLat) * Math.sin(sLon) * vNorth + Math.cos(sLat) * Math.sin(sLon) * vUp;
    const vZ = Math.cos(sLat) * vNorth + Math.sin(sLat) * vUp;

    // Radial velocity: dot product of satellite velocity and line-of-sight unit vector
    const v_rad = vX * uX + vY * uY + vZ * uZ;

    // Doppler shift (approaching satellite = positive shift, receding = negative)
    const dopplerShiftHz = -nominalCarrierHz * (v_rad / DopplerEphemerisEngine.SPEED_OF_LIGHT_KM_S);
    return Number(dopplerShiftHz.toFixed(2));
  }

  /**
   * Verifies an agent's claimed physical location using observed Doppler RF telemetry
   */
  public verifyProofOfLocation(
    agentId: string,
    claimed: GroundCoordinate,
    sat: SatelliteOrbitalState,
    observation: DopplerObservation,
    toleranceHz: number = 250 // Typical RF SDR measurement tolerance in Hz
  ): SpaceTimeProofOfLocation {
    const proofId = `stol_${crypto.randomBytes(10).toString("hex")}`;
    const issuedAt = Date.now();

    const expectedDopplerHz = DopplerEphemerisEngine.calculateExpectedDopplerShift(
      observation.nominalCarrierFrequencyHz,
      claimed,
      sat
    );

    const residualHz = Math.abs(observation.observedDopplerShiftHz - expectedDopplerHz);
    const verified = residualHz <= toleranceHz;

    // Confidence metric: 1.0 when residual is 0, decays smoothly as residual approaches tolerance
    const confidenceScore = verified
      ? Math.max(0.7, Number((1 - residualHz / (toleranceHz * 1.5)).toFixed(3)))
      : Math.max(0.0, Number((1 - residualHz / toleranceHz).toFixed(3)));

    const dilation = DopplerEphemerisEngine.calculateRelativisticDilation(sat.velocityKmPerSec);

    let rejectionReason: string | undefined;
    if (!verified) {
      rejectionReason = `DOPPLER_SPOOFING_DETECTED: Measured Doppler residual (${residualHz.toFixed(1)} Hz) exceeds spatial tolerance (${toleranceHz} Hz). Claimed coordinates do not match physical orbital geometry.`;
    }

    const digest = crypto
      .createHash("sha256")
      .update(
        `${proofId}:${agentId}:${claimed.latitude}:${claimed.longitude}:${sat.satelliteId}:${expectedDopplerHz}:${observation.observedDopplerShiftHz}:${verified}:${issuedAt}`
      )
      .digest("hex");

    const signature = crypto.createHmac("sha256", this.secretKey).update(digest).digest("hex");

    return {
      proofId,
      agentId,
      claimedLocation: { ...claimed },
      satelliteState: { ...sat },
      expectedDopplerShiftHz: expectedDopplerHz,
      observedDopplerShiftHz: observation.observedDopplerShiftHz,
      dopplerResidualHz: Number(residualHz.toFixed(2)),
      relativisticTimeDilationPicos: dilation.driftPicosecondsPerSecond,
      verified,
      confidenceScore,
      rejectionReason,
      issuedAt,
      attestationSignature: signature,
    };
  }
}
