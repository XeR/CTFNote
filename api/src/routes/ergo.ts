import { Request, Response, Handler } from "express";
import { Pool } from "pg";

type JwtType = {
  user_id: number;
  role: string;
  exp: number;
};

type JwtRow = {
  login: JwtType;
};

export function ergoRoute(pool: Pool): Handler {
  // Authenticates a (accountName, passphrase) couple
  async function authPassphrase(accountName: String, passphrase: String, ip: String): Promise<boolean> {
    try {
      await pool.query<JwtRow>(
        "SELECT login FROM ctfnote.login($1, $2)",
        [accountName, passphrase]
      );
    } catch {
      return false;
    }
    return true;
  }

  // Authenticates a (certfp, peerCerts) couple
  async function authCert(certfp: String, peerCerts: String, ip: String): Promise<boolean> {
    // TODO
    return false;
  }

  // Makes sure the body is correct and calls the appropriate function
  return async function (req: Request, res: Response): Promise<void> {
    // Make sure that the request contains everything we expect
    const { accountName, passphrase, certfp, peerCerts, ip } = req.body;

    // IP is always present
    if (typeof ip !== "string") {
      res.status(400).send("Invalid IP\n");
      return;
    }

    const isPw   = (accountName !== undefined || passphrase !== undefined);
    const isCert = (certfp !== undefined || peerCerts !== undefined);

    // If we have none, that's not good
    if (!isPw && !isCert) {
      res.status(400).send("Invalid authentication type\n");
      return;
    }

    // If we have both, that's not good either
    if (isPw && isCert) {
      res.status(400).send("Multiple authentication types\n");
      return;
    }

    if (isPw) {
      if (typeof accountName !== "string") {
        res.status(400).send("accountName is not a string\n");
        return;
      }

      if (typeof passphrase !== "string") {
        res.status(400).send("passphrase is not a string\n");
        return;
      }

      if (await authPassphrase(accountName, passphrase, ip)) {
        res.json({"success": true});
        return;
      }
    } else if (isCert) {
      console.log(certfp, peerCerts, ip);

      if (typeof certfp !== "string") {
        res.status(400).send("certfp is not a string\n");
        return;
      }

      if (typeof peerCerts !== "string") {
        res.status(400).send("peerCerts is not a string\n");
        return;
      }

      if (await authCert(certfp, peerCerts, ip)) {
        res.json({"success": true});
        return;
      }
    }

    // Fallback
    res.status(403).json({"success": false});
  };
}
