package generator;
import src.PA;
import uniandes.gload.core.Task;
import uniandes.gload.examples.clientserver.Client;

public class ClientServerTask extends Task{
	
	private Generator generator;
	
	public ClientServerTask(Generator generator){
		super();
		this.generator = generator;
	}

	@Override
	public void fail() {
		generator.aumentarFallidas();
		System.out.println(Task.MENSAJE_FAIL);
	}

	@Override
	public void success() {
		System.out.println(Task.OK_MESSAGE);
		
	}

	@Override
	public void execute() {
		try{
			//Cliente cliente = new Cliente();
			PA p = new PA("192.168.0.3","12");
			p.iniciarProtocoloSeguro();
		}
		catch (Exception e){
			fail();
		}
	}
	
	

}
