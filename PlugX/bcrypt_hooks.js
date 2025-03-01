Interceptor.attach(Module.getExoprtByName('bcrypt.dll', 'BCryptDecrypt'), {
    onEnter: function (args) {
        console.log("\n----- [BCryptDecrypt] -----");
        this.pClearTxt = args[6];
        this.size = args[7];
        if (this.pClearTxt.isNull()) {
            return;
        }
        this.clearTxtSize = this.size.readU64();
    },
    onLeave: function(retval) {
        if (this.clearTxtSize == 0) {
            return;
        }

        try {
            let clearTxt = this.pClearTxt.readCString(this.clearTxtSize);
            if (clearTxt != null) {
                console.log(clearTxt);
            }
        } catch (err) {
            console.log(err);
        }
    }
});

Interceptor.attach(Module.getExoprtByName('bcrypt.dll', 'BCryptOpenAlgorithmProvider'), {
    onEnter: function (args) {
        console.log("\n----- [BCryptOpenAlgorithmProvider] -----");
        
        let algId = args[1].isNull() ? "NULL" : args[1].readUtf16String();
        let impl = args[2].isNull() ? "NULL" : args[2].readUtf16String();
        let flags = args[3].toInt32(); 

        console.log(" | Algorithm:", algId);
        console.log(" | Implementation:", impl);
        console.log(" | Flags:", flags.toString(16)); 
    }
});


Interceptor.attach(Module.getExoprtByName('bcrypt.dll', 'BCryptEncrypt'), {
    onEnter: function (args) {
        console.log("\n----- [BCryptEncrypt] -----");

        this.pClearTxt = args[1]; 
        this.clearTxtSize = args[2].toInt32();

        if (!this.pClearTxt.isNull() && this.clearTxtSize > 0) {
            try {
                let clearTxt = this.pClearTxt.readCString(this.clearTxtSize);
                console.log(clearTxt);
            } catch (err) {
                console.log(err);
            }
        }
    }
});
