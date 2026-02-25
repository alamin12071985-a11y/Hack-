def main():
    # Groq Available Check
    if not GROQ_AVAILABLE:
        print("⚠️ WARNING: Groq not installed. Run: pip install groq")

    # Bot Token Check
    if not BOT_TOKEN or BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ ERROR: BOT_TOKEN is missing or not set in Environment Variables!")
        return

    print("="*50)
    print("🚀 সুপার অ্যাডভান্সড বট চালু হচ্ছে...")
    print("="*50)

    try:
        # --- Version 20 এর জন্য সঠিক স্ট্রাকচার ---
        # 'Application' অবজেক্ট তৈরি করা হচ্ছে
        application = Application.builder().token(BOT_TOKEN).build()

        # Handlers যোগ করা হচ্ছে
        application.add_handler(CommandHandler("start", start))
        application.add_handler(CommandHandler("help", help_command))
        application.add_handler(CallbackQueryHandler(button_handler))
        application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
        application.add_handler(MessageHandler(filters.Document.ALL, handle_document))
        
        # Error Handler
        application.add_error_handler(error_handler)

        # --- Webhook Setup for Render ---
        PORT = int(os.environ.get('PORT', 8443))
        RENDER_EXTERNAL_URL = os.environ.get('RENDER_EXTERNAL_URL')

        if RENDER_EXTERNAL_URL:
            # Render Web Service Mode
            print(f"🌐 Web Service Mode (Render)")
            print(f"🔗 Setting Webhook to: {RENDER_EXTERNAL_URL}/{BOT_TOKEN}")
            
            application.run_webhook(
                listen="0.0.0.0",
                port=PORT,
                url_path=BOT_TOKEN,
                webhook_url=f"{RENDER_EXTERNAL_URL}/{BOT_TOKEN}"
            )
        else:
            # Local Polling Mode
            print("💻 Local Polling Mode")
            print("⚠️ Note: For Render deployment, set RENDER_EXTERNAL_URL env var.")
            application.run_polling(allowed_updates=Update.ALL_TYPES)

    except Exception as e:
        print(f"❌ Critical Error in main execution: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
