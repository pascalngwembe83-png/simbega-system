export async function onRequestGet({ env }) {
  try {
    const result = await env.DB.prepare("SELECT 1 AS ok").first();

    return Response.json({
      success: true,
      database: "connected",
      result
    });
  } catch (error) {
    return Response.json({
      success: false,
      error: "Database connection failed"
    }, { status: 500 });
  }
}
