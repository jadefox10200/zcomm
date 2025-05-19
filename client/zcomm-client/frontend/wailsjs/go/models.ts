export namespace core {
	
	export class BasketDispatch {
	    dispatch_id: string;
	    to_zid: string;
	    from_zid: string;
	    subject: string;
	    timestamp: number;
	    is_end: boolean;
	    status: string;
	
	    static createFrom(source: any = {}) {
	        return new BasketDispatch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.dispatch_id = source["dispatch_id"];
	        this.to_zid = source["to_zid"];
	        this.from_zid = source["from_zid"];
	        this.subject = source["subject"];
	        this.timestamp = source["timestamp"];
	        this.is_end = source["is_end"];
	        this.status = source["status"];
	    }
	}
	export class Dispatch {
	    uuid: string;
	    from_zid: string;
	    to_zid: string;
	    CC: string[];
	    subject: string;
	    body: string;
	    local_nonce: string;
	    nonce: string;
	    timestamp: number;
	    conversation_id: string;
	    signature: string;
	    ephemeral_pub_key: string;
	    is_end: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Dispatch(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.uuid = source["uuid"];
	        this.from_zid = source["from_zid"];
	        this.to_zid = source["to_zid"];
	        this.CC = source["CC"];
	        this.subject = source["subject"];
	        this.body = source["body"];
	        this.local_nonce = source["local_nonce"];
	        this.nonce = source["nonce"];
	        this.timestamp = source["timestamp"];
	        this.conversation_id = source["conversation_id"];
	        this.signature = source["signature"];
	        this.ephemeral_pub_key = source["ephemeral_pub_key"];
	        this.is_end = source["is_end"];
	    }
	}

}

export namespace main {
	
	export class Contact {
	    Alias: string;
	    ZID: string;
	    EdPub: string;
	    EcdhPub: string;
	    LastUpdated: number;
	
	    static createFrom(source: any = {}) {
	        return new Contact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Alias = source["Alias"];
	        this.ZID = source["ZID"];
	        this.EdPub = source["EdPub"];
	        this.EcdhPub = source["EcdhPub"];
	        this.LastUpdated = source["LastUpdated"];
	    }
	}
	export class ConvSummary {
	    ConID: string;
	    Subject: string;
	    Ended: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ConvSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ConID = source["ConID"];
	        this.Subject = source["Subject"];
	        this.Ended = source["Ended"];
	    }
	}
	export class  {
	    DispID: string;
	    SeqNo: number;
	
	    static createFrom(source: any = {}) {
	        return new (source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.DispID = source["DispID"];
	        this.SeqNo = source["SeqNo"];
	    }
	}
	export class Conversation {
	    ConID: string;
	    Subject: string;
	    Dispatches: [];
	    Ended: boolean;
	
	    static createFrom(source: any = {}) {
	        return new Conversation(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ConID = source["ConID"];
	        this.Subject = source["Subject"];
	        this.Dispatches = this.convertValues(source["Dispatches"], );
	        this.Ended = source["Ended"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

