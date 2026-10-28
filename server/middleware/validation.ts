import { Request, Response, NextFunction } from "express";
import { z } from "zod";

/**
 * Reusable declarative Zod schema validation middleware.
 * Guarantees sanitized, strictly-typed request bodies and eliminates prototype pollution.
 */
export const validateBody = <T>(schema: z.ZodSchema<T>) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.body);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const message = issue ? issue.message : "Validation error";
      res.status(400).json({ success: false, error: message });
      return;
    }
    req.body = parsed.data;
    next();
  };
};

/**
 * Reusable declarative Zod schema validation for query parameters.
 */
export const validateQuery = <T>(schema: z.ZodSchema<T>) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const parsed = schema.safeParse(req.query);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const message = issue ? issue.message : "Validation error";
      res.status(400).json({ success: false, error: message });
      return;
    }
    req.query = parsed.data as any;
    next();
  };
};
